import {createV2Explorer} from './v2-bootstrap.js';
import {
  createApplicationRuntime,
  createSecretsRuntime,
  applicationSnapshotFromLegacy,
  applicationDescriptorFromLegacy,
  type ApplicationRuntime,
  type ApplicationSnapshot,
  type ApplicationPrepareContext,
  type SecretsRuntime,
} from '@kick-playr/local-key-vault/runtime-client';
import {
  createExplorerSecrets,
  createExplorerSecretsFromSnapshot,
  liveExplorerProcessPolicy,
  type ExplorerSecrets,
  type TenantSnapshotLoader,
} from './secrets.js';
import {
  forwardApplication,
  ownedApplication,
  type ComposedApplication,
  type OwnedApplication,
} from './live-application.js';
import type { RequestListener } from 'node:http';
import { StartupDiagnostics } from './startup-diagnostics.js';

type RuntimeOptions = Parameters<
  typeof createApplicationRuntime<OwnedApplication>
>[0];
export type LiveExplorerOptions = {
  compose: (secrets: ExplorerSecrets) => Promise<ComposedApplication>;
  legacyFactory?: () => SecretsRuntime;
  runtimeFactory?: (
    options: RuntimeOptions,
  ) => ApplicationRuntime<OwnedApplication>;
  operationTimeoutMs?: number;
  tenantLoader?: TenantSnapshotLoader;
  /** Holds all verified tenant controller leases through HTTP completion. */
  withTenantAdmission?: (
    operation: (signal: AbortSignal) => Promise<void>,
    signal: AbortSignal,
  ) => Promise<void>;
  /** Optional only after a durable migration coordinator verifies storage and tenant revisions.
   * Returned secrets must read the verified tenant snapshot; composition reloads control DB state.
   */
  prepareMigration?: (
    snapshot: ApplicationSnapshot,
    context: ApplicationPrepareContext,
  ) => Promise<ExplorerSecrets>;
};
const unavailable = () => Error('Explorer application unavailable');
/** The HTTP listener stays fixed; every serving generation owns its entire Nest graph. */
export function createLiveExplorer(
  environmentInput: NodeJS.ProcessEnv,
  options: LiveExplorerOptions,
) {
  if(environmentInput.VAULT_APPLICATION_ID)return createV2Explorer(environmentInput,options);
  const environment = { ...environmentInput };
  const strategy = environment.SECRETS_KEYS_STRATEGY ?? 'ENV_VARIABLES';
  const operationTimeoutMs = options.operationTimeoutMs ?? 30000;
  let closed = false,
    liveRequested = false,
    liveStarted = false,
    warning = false;
  let legacySecrets: ExplorerSecrets | undefined,
    legacyApp: OwnedApplication | undefined;
  let live: ApplicationRuntime<OwnedApplication> | undefined,
    probe: ApplicationRuntime<OwnedApplication> | undefined;
  let pending: Promise<void> | undefined,
    timer: ReturnType<typeof setTimeout> | undefined;
  let modeUntil = 0;
  const legacyOperations = new Set<AbortController>();
  const applications = new Set<OwnedApplication>();
  function own(application: ComposedApplication) {
    const owned = ownedApplication({
      handler: application.handler,
      close: async () => {
        try {
          await application.close();
        } finally {
          applications.delete(owned);
        }
      },
    });
    applications.add(owned);
    return owned;
  }
  const factory = (config: RuntimeOptions) =>
    options.runtimeFactory?.(config) ?? createApplicationRuntime(config);
  const openLegacy = () =>
    options.legacyFactory?.() ?? createSecretsRuntime({ environment });
  function validLegacy() {
    return (
      !!legacyApp &&
      (strategy === 'ENV_VARIABLES' ||
        (!!legacySecrets?.processSnapshot &&
          legacySecrets.processSnapshot.secrets.every(
            (s) =>
              s.attributes.enabled &&
              (s.attributes.exp === undefined ||
                s.attributes.exp * 1000 > Date.now()) &&
              (s.attributes.nbf === undefined ||
                s.attributes.nbf * 1000 <= Date.now()),
          )))
    );
  }
  async function composeSecrets(secrets: ExplorerSecrets) {
    try {
      const app = own(await options.compose(secrets));
      if (closed) {
        await app.close();
        throw unavailable();
      }
      return { value: app, dispose: () => app.close() };
    } catch (error) {
      secrets.close();
      throw error;
    }
  }
  async function prepare(snapshot: ApplicationSnapshot) {
    return composeSecrets(
      await createExplorerSecretsFromSnapshot(
        environment,
        snapshot,
        openLegacy(),
        options.tenantLoader,
      ),
    );
  }
  function configuration(): RuntimeOptions {
    return {
      application: 'explorer-api',
      scope: {
        environment: environment.LOCAL_KEYVAULT_ENVIRONMENT ?? 'development',
        tenant: '_shared',
      },
      environment,
      allowedMappings: liveExplorerProcessPolicy(environment).allowedMappings,
      requiredMappings: liveExplorerProcessPolicy(environment).requiredMappings,
      intervalMs: 1000,
      operationTimeoutMs,
      prepare,
      ...(options.prepareMigration
        ? {
            prepareMigration: async (
              snapshot: ApplicationSnapshot,
              context: ApplicationPrepareContext,
            ) =>
              composeSecrets(
                await options.prepareMigration!(snapshot, context),
              ),
          }
        : {}),
      // No prepareMigration by default: environment-pointer swaps cannot migrate storage.
    };
  }
  async function perform(force: boolean) {
    if (closed) throw unavailable();
    if (strategy === 'ENV_VARIABLES') {
      if (!legacyApp) {
        legacySecrets = await createExplorerSecrets(environment);
        try {
          legacyApp = own(await options.compose(legacySecrets));
        } catch (error) {
          legacySecrets.close();
          throw error;
        }
      }
      return;
    }
    if (strategy !== 'LOCAL_KEYVAULT') throw unavailable();
    if (!liveRequested) {
      probe ??= factory(configuration());
      if (force || Date.now() >= modeUntil) {
        try {
          liveRequested = (await probe.mode()) === 'live';
          modeUntil = Date.now() + 1000;
          warning = false;
        } catch {
          warning = true;
          if (!validLegacy() || probe.status().reason === 'AccessDenied')
            throw unavailable();
          return;
        }
      }
      if (!liveRequested) {
        if (!legacyApp) {
          legacySecrets = await createExplorerSecrets(
            environment,
            openLegacy(),
            undefined,
            options.tenantLoader,
          );
          try {
            legacyApp = own(await options.compose(legacySecrets));
          } catch (error) {
            legacySecrets.close();
            throw error;
          }
        }
        if (!validLegacy() || probe.status().reason === 'AccessDenied')
          throw unavailable();
        return;
      }
    }
    if (!live) {
      if (liveExplorerProcessPolicy(environment).unsupportedMappings.length)
        throw unavailable();
      const seededApp = legacyApp;
      const initial =
        seededApp && legacySecrets?.processSnapshot
          ? {
              snapshot: applicationSnapshotFromLegacy(
                'explorer-api',
                legacySecrets.processSnapshot,
              ),
              prepared: { value: seededApp, dispose: () => seededApp.close() },
            }
          : undefined;
      let baseline;
      if (!initial) {
        const metadata = openLegacy();
        try {
          const binding = await metadata.loadApplication('explorer-api');
          baseline = applicationDescriptorFromLegacy(
            'explorer-api',
            binding.scope,
            binding.request,
          );
        } finally {
          metadata.close();
        }
      }
      live = factory({
        ...configuration(),
        ...(initial ? { initial } : { baseline }),
      });
    }
    await live.start();
    liveStarted = true;
    legacyApp = undefined;
    legacySecrets = undefined;
    if (force) await live.refresh();
    probe?.close();
    probe = undefined;
  }
  function read(force = false): Promise<void> {
    pending ??= perform(force).finally(() => {
      pending = undefined;
      if (!closed && !liveStarted && !timer) {
        timer = setTimeout(() => {
          timer = undefined;
          void read(true).catch(() => {});
        }, 1000);
        timer.unref?.();
      }
    });
    return pending;
  }
  const handler: RequestListener = (request, response) => {
    void (async () => {
      await read();
      if (liveStarted && live) {
        await live.withValue((app, context) =>
          options.withTenantAdmission
            ? options.withTenantAdmission(
                (tenantSignal) =>
                  forwardApplication(
                    app,
                    request,
                    response,
                    AbortSignal.any([context.signal, tenantSignal]),
                  ),
                context.signal,
              )
            : forwardApplication(app, request, response, context.signal),
        );
      } else {
        if (
          !validLegacy() ||
          (strategy === 'LOCAL_KEYVAULT' &&
            probe?.status().reason === 'AccessDenied')
        )
          throw unavailable();
        const admittedApplication = legacyApp!;
        const controller = new AbortController();
        legacyOperations.add(controller);
        const deadline = setTimeout(
          () => controller.abort(),
          operationTimeoutMs,
        );
        deadline.unref?.();
        try {
          if (options.withTenantAdmission)
            await options.withTenantAdmission(
              (tenantSignal) =>
                forwardApplication(
                  admittedApplication,
                  request,
                  response,
                  AbortSignal.any([controller.signal, tenantSignal]),
                ),
              controller.signal,
            );
          else
            await forwardApplication(
              admittedApplication,
              request,
              response,
              controller.signal,
            );
        } finally {
          clearTimeout(deadline);
          legacyOperations.delete(controller);
        }
      }
    })().catch(() => {
      if (response.destroyed || response.writableEnded) return;
      if (response.headersSent) response.destroy();
      else {
        response.writeHead(503, {
          'Cache-Control': 'no-store',
          'Content-Type': 'application/json',
        });
        response.end('{"error":"Explorer application unavailable"}');
      }
    });
  };
  return {
    initialize: () => read(true),
    refresh: () => read(true),
    handler,
    status: () => {
      if (live) return live.status();
      if (probe?.status().reason === 'AccessDenied')
        return { state: 'blocked', reason: 'AccessDenied' };
      if (legacyApp && !validLegacy())
        return { state: 'blocked', reason: 'InUseExpired' };
      return {
        state: warning ? 'warning' : 'legacy',
        ...(warning ? { reason: 'DiscoveryUnavailable' } : {}),
      };
    },
    close: async () => {
      if (closed) return;
      closed = true;
      clearTimeout(timer);
      for (const operation of legacyOperations) operation.abort();
      probe?.close();
      live?.close();
      await pending?.catch(() => {});
      await Promise.all([...applications].map((app) => app.close()));
      applications.clear();
      legacySecrets?.close();
    },
  };
}

export async function startLiveExplorer(
  environment: NodeJS.ProcessEnv,
  diagnostics: StartupDiagnostics,
) {
  const source = createLiveExplorer(environment, {
    compose: async (secrets) => {
      // Loading and validating process secrets always precedes dependent imports.
      const { composeApplication } = await diagnostics.run(
        'server.import',
        () => import('./bootstrap.js'),
      );
      return composeApplication(secrets, diagnostics);
    },
  });
  const { createServer } = await import('node:http');
  const server = createServer(source.handler);
  try {
    await diagnostics.run('secrets.process', () => source.initialize());
    const port = Number(environment.PORT ?? 3003);
    if (!Number.isInteger(port) || port < 1 || port > 65535)
      throw unavailable();
    await diagnostics.run(
      'server.listen',
      () =>
        new Promise<void>((resolve, reject) => {
          server.once('error', reject);
          server.listen(port, environment.HOST ?? '127.0.0.1', () => {
            server.off('error', reject);
            resolve();
          });
        }),
    );
  } catch (error) {
    await source.close();
    throw error;
  }
  const close = () => {
    server.close();
    void source.close();
  };
  process.once('SIGINT', close);
  process.once('SIGTERM', close);
  return { server, source };
}
