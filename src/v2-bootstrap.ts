import {
  createBootstrapClient,
  type BootstrapSnapshot,
  type BootstrapContext,
} from '@kick-playr/local-key-vault/runtime-client/bootstrap';
import {
  createMemoryRuntime,
  type SecretsRuntime,
  type RuntimeSnapshot,
} from '@kick-playr/local-key-vault/runtime-client';
import {
  ExplorerSecrets,
  type SecretKeyBinding,
  type TenantSecretIdentity,
} from './secrets.js';
import {
  ownedApplication,
  forwardApplication,
  type ComposedApplication,
  type OwnedApplication,
} from './live-application.js';
import type { IncomingMessage, ServerResponse } from 'node:http';
function scalar(context: BootstrapContext) {
  if (!context.ready) throw Error('Tenant static secrets unavailable');
  return Object.fromEntries(
    context.values
      .filter((r) => r.kind !== 'integration')
      .map((r) => [r.accessName, r.value as string]),
  );
}
/** A composed Nest graph owns one pinned view. The parent client alone refreshes Vault. */
export function explorerSecretsFromV2(
  input: NodeJS.ProcessEnv,
  snapshot: BootstrapSnapshot,
): ExplorerSecrets {
  const context = (id?: string) => {
    const c = id ? snapshot.tenants[id] : snapshot.application;
    if (!c?.ready) throw Error('Static secrets unavailable');
    return c;
  };
  const environment = {
      ...Object.fromEntries(
        Object.entries(input).filter(([name]) =>
          [
            'NODE_ENV',
            'PORT',
            'HOST',
            'VAULT_APPLICATION_ID',
            'VAULT_ENVIRONMENT',
            'VAULT_URL',
          ].includes(name),
        ),
      ),
      ...scalar(context()),
      SECRETS_KEYS_STRATEGY: 'LOCAL_KEYVAULT',
      EXPLORER_CONTROL_DATABASE: 'control-kick-playr',
    },
    source = {
      load: async () => scalar(context()),
      status: () => ({
        state: 'applied',
        ready: true,
        connected: true,
        revision: snapshot.revision,
      }),
      tenantIds: () => Object.keys(snapshot.tenants),
      context,
      tenant: (id: string) => scalar(context(id)),
      integration: (id: string, name: string) => {
        const row = context(id).values.find(
          (r) =>
            r.kind === 'integration' &&
            (r.resourceId === name || r.name === name),
        );
        if (!row) throw Error('Integration unavailable');
        return row;
      },
      refresh: async () => {},
      close: () => {},
    };
  for (const name of [
    'EXPLORER_MONGODB_URI',
    'WORKFLOW_SHARED_WRAPPING_KEY_V1',
    'EXPLORER_CREDENTIAL_KEY',
    'MANAGER_SETUP_CONTROL_KEY',
    'CLERK_SECRET_KEY',
  ])
    if (!scalar(context())[name])
      throw Error('Required Explorer static secret missing');
  const runtime = createMemoryRuntime(
    source,
    'explorer-api',
    snapshot.environment,
  );
  class PinnedSecrets extends ExplorerSecrets {
    override integration(identity: TenantSecretIdentity, reference: string) {
      if (identity.environment !== snapshot.environment) throw Error('Tenant static scope mismatch');
      return source.integration(identity.tenantId, reference);
    }
    override async initializeTenant(identity: TenantSecretIdentity) {
      if (identity.environment !== snapshot.environment)
        throw Error('Tenant environment mismatch');
      context(identity.tenantId);
    }
    override tenantEnvironment(binding: SecretKeyBinding) {
      if (
        binding.environment !== snapshot.environment ||
        binding.keyReference !== `workflow-local:${binding.tenantId}:key`
      )
        throw Error('Tenant key scope mismatch');
      const values = scalar(context(binding.tenantId));
      return Object.freeze(
        Object.fromEntries(
          Object.values(binding.variables).map((name) => {
            const row = context(binding.tenantId).values.find(
              (r) => r.accessName === name && r.kind === 'encryption-key',
            );
            if (!row) throw Error('Tenant key unavailable');
            const bytes = Buffer.from(
              String(row.value),
              row.valueFormat === 'hex64' ? 'hex' : 'base64',
            );
            try {
              if (bytes.length !== 32) throw Error('Invalid tenant key');
              return [name, bytes.toString('base64')];
            } finally {
              bytes.fill(0);
            }
          }),
        ),
      );
    }
    override describe(binding: SecretKeyBinding) {
      this.tenantEnvironment(binding);
      const rows = context(binding.tenantId).values;
      return {
        generation: parseInt(
          snapshot.revision.replace(/[^a-f0-9]/g, '').slice(0, 8) || '1',
          16,
        ),
        version: binding.version ?? 'v1',
        versions: Object.fromEntries(
          Object.entries(binding.variables).map(([role, name]) => [
            role,
            rows.find((r) => r.accessName === name)!.versionId,
          ]),
        ) as { wrapping: string; index: string; control: string },
      };
    }
    override secret(identity: TenantSecretIdentity, reference: unknown) {
      if (
        identity.environment !== snapshot.environment ||
        typeof reference !== 'string' ||
        !/^vault:[A-Z][A-Z0-9_]{0,127}$/.test(reference)
      )
        throw Error('Tenant static scope mismatch');
      const row = context(identity.tenantId).values.find(
        (r) => r.accessName === reference.slice(6),
      );
      if (!row) throw Error('Tenant static secret unavailable');
      return typeof row.value === 'string'
        ? row.value
        : JSON.stringify(row.value);
    }
  }
  return new PinnedSecrets(
    'LOCAL_KEYVAULT',
    Object.freeze(environment),
    runtime,
  );
}
export function createV2Explorer(
  environment: NodeJS.ProcessEnv,
  options: {
    compose: (secrets: ExplorerSecrets) => Promise<ComposedApplication>;
    clientFactory?: typeof createBootstrapClient;
  },
) {
  if (environment.VAULT_APPLICATION_ID !== 'explorer-api')
    throw Error('Vault application identity mismatch');
  let active: OwnedApplication | undefined,
    closed = false;
  const owned = new Set<OwnedApplication>();
  const aborts = new Set<AbortController>();
  const client = (options.clientFactory ?? createBootstrapClient)({
    url: environment.VAULT_URL!,
    applicationId: 'explorer-api',
    environment: environment.VAULT_ENVIRONMENT!,
    grant: environment.VAULT_GRANT!,
    registerInstances: true,
    env: {},
    onDiagnostic: (message) => console.error(message),
    onChange: async (next) => {
      if (!next?.application.ready) {
        active = undefined;
        for (const c of aborts) c.abort();
        return;
      }
      const graph = ownedApplication(
        await options.compose(explorerSecretsFromV2(environment, next)),
      );
      owned.add(graph);
      if (closed) {
        await graph.close();
        return;
      }
      const previous = active;
      active = graph;
      if (previous) void previous.close().finally(() => owned.delete(previous));
    },
  });
  return {
    initialize: () => client.start(),
    refresh: () => client.refresh(),
    status: () => ({
      state: client.status().ready ? 'applied' : 'blocked',
      reason: undefined as string | undefined,
      ...client.status(),
    }),
    handler: (req: IncomingMessage, res: ServerResponse) => {
      if (closed || !client.status().ready || !active) {
        res.writeHead(503, {
          'content-type': 'application/json',
          'cache-control': 'no-store',
        });
        res.end(JSON.stringify({ error: 'Key Vault is not connected' }));
        return;
      }
      const controller = new AbortController();
      aborts.add(controller);
      void forwardApplication(active, req, res, controller.signal).finally(() =>
        aborts.delete(controller),
      );
    },
    close: async () => {
      closed = true;
      client.close();
      for (const c of aborts) c.abort();
      await Promise.all([...owned].map((app) => app.close()));
      owned.clear();
    },
  };
}
