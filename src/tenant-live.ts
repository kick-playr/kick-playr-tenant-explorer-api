import { createHash } from 'node:crypto';
import {
  createApplicationRuntime,
  createSecretsRuntime,
  applicationDescriptorFromTenantLegacy,
  applicationSnapshotFromTenantLegacy,
  parseSnapshotRequest,
  bindingDigest,
  type ApplicationDescriptor,
  type ApplicationSnapshot,
  type RuntimeSnapshot,
  type RuntimeSnapshotRequest,
  type ApplicationRuntime,
  type SecretsRuntime,
} from '@kick-playr/local-key-vault/runtime-client';
import {
  createMongoTenantRotationStore,
  rotationKeyDigest,
  type RotationKeys,
} from '@kick-playr/local-key-vault/runtime-client/tenant-rotation';
import type { MongoClient } from 'mongodb';
import type { RequestHandler } from 'express';
import {
  ExplorerSecrets,
  processNames,
  type SecretKeyBinding,
  type TenantSecretIdentity,
} from './secrets.js';
import { loadExplorerConfiguration } from './database-config.js';
const roles = ['wrapping', 'index', 'control'] as const;
const fail = () => Error('Tenant secrets unavailable');
function physical(binding: SecretKeyBinding, role: (typeof roles)[number]) {
  return (
    `tk-${role}-` +
    createHash('sha256')
      .update(
        JSON.stringify([
          binding.environment,
          binding.tenantId,
          binding.keyReference,
          role === 'wrapping' ? 'wrapping/v1' : role,
        ]),
      )
      .digest('hex')
  );
}
export function tenantApplicationDescriptor(
  binding: SecretKeyBinding,
  input: RuntimeSnapshotRequest,
): ApplicationDescriptor {
  const request = parseSnapshotRequest(input);
  const set = request.keySets.find(
    (set) => set.reference === binding.keyReference,
  );
  if (
    !set ||
    roles.some((role) => set.mappings[role] !== binding.variables[role])
  )
    throw fail();
  return applicationDescriptorFromTenantLegacy(
    'explorer-api',
    { environment: binding.environment, tenant: binding.tenantId },
    request,
  );
}

export function tenantSnapshotFromApplication(
  binding: SecretKeyBinding,
  revision: number,
  snapshot: ApplicationSnapshot,
  previous?: RuntimeSnapshot,
): RuntimeSnapshot {
  if (
    snapshot.application !== 'explorer-api' ||
    snapshot.scope.environment !== binding.environment ||
    snapshot.scope.tenant !== binding.tenantId ||
    !Number.isSafeInteger(revision) ||
    revision < 1
  )
    throw fail();
  const resources = Object.fromEntries(
    roles.map((role) => {
      const resource = snapshot.resources.find(
        (r) => r.mapping === binding.variables[role],
      );
      if (
        !resource ||
        resource.name !== physical(binding, role) ||
        resource.classification !== 'encryption-key'
      )
        throw fail();
      const decoded = Buffer.from(resource.value, 'base64');
      if (
        decoded.length !== 32 ||
        decoded.toString('base64') !== resource.value
      ) {
        decoded.fill(0);
        throw fail();
      }
      decoded.fill(0);
      return [role, resource];
    }),
  ) as Record<(typeof roles)[number], ApplicationSnapshot['resources'][number]>;
  const old = previous?.keySets.find(
    (set) => set.reference === binding.keyReference,
  );
  const same = old?.wrappingVersions.find(
    (w) => w.vaultVersion === resources.wrapping.version,
  );
  const keyVersion =
    binding.version ??
    same?.keyVersion ??
    `vault-${resources.wrapping.version}`;
  if (
    old?.wrappingVersions.some(
      (w) =>
        w.keyVersion === keyVersion &&
        w.vaultVersion !== resources.wrapping.version,
    )
  )
    throw fail();
  const wrap = {
    keyVersion,
    vaultVersion: resources.wrapping.version,
    value: resources.wrapping.value,
    attributes: resources.wrapping.attributes,
  };
  // Every old wrapping reference remains available under its immutable label.
  const history =
    old?.wrappingVersions.filter((w) => w.keyVersion !== keyVersion) ?? [];
  const set = {
    reference: binding.keyReference,
    mappings: { ...binding.variables },
    currentWrappingVersion: keyVersion,
    wrappingVersions: [...history, wrap],
    index: {
      vaultVersion: resources.index.version,
      value: resources.index.value,
      attributes: resources.index.attributes,
    },
    control: {
      vaultVersion: resources.control.version,
      value: resources.control.value,
      attributes: resources.control.attributes,
    },
  };
  const body = {
    schemaVersion: 1 as const,
    bindingRevision: revision,
    keySets: [
      {
        reference: set.reference,
        mappings: set.mappings,
        currentWrappingVersion: keyVersion,
        wrappingVersions: set.wrappingVersions.map(
          ({ keyVersion, vaultVersion }) => ({ keyVersion, vaultVersion }),
        ),
        indexVersion: set.index.vaultVersion,
        controlVersion: set.control.vaultVersion,
      },
    ],
    secrets: snapshot.resources
      .filter(
        (r) => !roles.some((role) => r.mapping === binding.variables[role]),
      )
      .map((r) => ({
        mapping: r.mapping,
        purpose: r.name,
        version: r.version,
      })),
  };
  return {
    schemaVersion: 1,
    environment: binding.environment,
    tenant: binding.tenantId,
    bindingRevision: revision,
    bindingDigest: bindingDigest(body),
    generation: snapshot.generation,
    loadedAt: Date.now(),
    keySets: [set],
    secrets: body.secrets.map((secret) => {
      const r = snapshot.resources.find((r) => r.mapping === secret.mapping)!;
      return { ...secret, value: r.value, attributes: r.attributes };
    }),
  };
}

/** Stable across ordinary credential generations: only the three bound crypto pins count. */
export function tenantKeyDigest(
  target: ApplicationDescriptor,
  binding: SecretKeyBinding,
): string {
  if (
    target.scope.environment !== binding.environment ||
    target.scope.tenant !== binding.tenantId
  )
    throw fail();
  const selected = roles.map((role) => {
    const matches = target.resources.filter(
      (resource) => resource.mapping === binding.variables[role],
    );
    if (
      matches.length !== 1 ||
      matches[0]!.name !== physical(binding, role) ||
      matches[0]!.classification !== 'encryption-key'
    )
      throw fail();
    return [role, matches[0]!.name, matches[0]!.version];
  });
  return rotationKeyDigest(
    target.scope,
    Object.fromEntries(
      selected.map(([role, name, version]) => [role, { name, version }]),
    ) as RotationKeys,
  );
}
export function verifiedRotation(
  proof: any,
  target: ApplicationDescriptor,
  binding: SecretKeyBinding,
  revision: number,
): boolean {
  let expectedDigest: string;
  try {
    expectedDigest = tenantKeyDigest(target, binding);
  } catch {
    return false;
  }
  return (
    !!proof &&
    proof.stage === 'completed' &&
    proof.scope?.environment === binding.environment &&
    proof.scope?.tenant === binding.tenantId &&
    proof.toDigest === expectedDigest &&
    Number.isSafeInteger(proof.activatedRevision) &&
    proof.activatedRevision <= revision &&
    roles.every((role) => {
      const resource = target.resources.find(
        (r) => r.mapping === binding.variables[role],
      );
      return (
        !!resource &&
        proof.to?.[role]?.name === resource.name &&
        proof.to?.[role]?.version === resource.version
      );
    })
  );
}
export function validTenantSnapshot(snapshot: RuntimeSnapshot): boolean {
  return [
    ...snapshot.secrets,
    ...snapshot.keySets.flatMap((set) => [
      ...set.wrappingVersions,
      set.index,
      set.control,
    ]),
  ].every(
    (resource) =>
      resource.attributes.enabled &&
      (resource.attributes.exp === undefined ||
        resource.attributes.exp * 1000 > Date.now()) &&
      (resource.attributes.nbf === undefined ||
        resource.attributes.nbf * 1000 <= Date.now()),
  );
}
/** Exact key-only pins need no v1 manifest publication and no obsolete provider secrets. */
export function rotationSnapshotRequest(
  binding: SecretKeyBinding,
  proof: any,
  revision: number,
): RuntimeSnapshotRequest {
  if (
    proof?.stage !== 'completed' ||
    proof.scope?.environment !== binding.environment ||
    proof.scope?.tenant !== binding.tenantId ||
    !Number.isSafeInteger(proof.activatedRevision) ||
    proof.activatedRevision > revision ||
    binding.version !== proof.wrappingKeyVersion ||
    proof.wrappingKeyVersion !== proof.to?.wrapping?.version ||
    !Array.isArray(proof.wrappingHistory) ||
    proof.wrappingHistory.length > 64 ||
    !roles.every(
      (role) =>
        proof.to?.[role]?.name === physical(binding, role) &&
        /^[a-f0-9]{32}$/.test(proof.to?.[role]?.version),
    )
  )
    throw fail();
  const history = proof.wrappingHistory.map((entry: any) => {
    if (
      entry.name !== physical(binding, 'wrapping') ||
      !/^[a-f0-9]{32}$/.test(entry.version) ||
      typeof entry.keyVersion !== 'string' ||
      !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(entry.keyVersion)
    )
      throw fail();
    return {
      keyVersion: entry.keyVersion as string,
      vaultVersion: entry.version as string,
    };
  });
  const target = {
    keyVersion: proof.wrappingKeyVersion as string,
    vaultVersion: proof.to.wrapping.version as string,
  };
  if (
    history.some(
      (entry: { keyVersion: string; vaultVersion: string }) =>
        entry.keyVersion === target.keyVersion &&
        entry.vaultVersion !== target.vaultVersion,
    )
  )
    throw fail();
  if (
    !history.some(
      (entry: { keyVersion: string }) => entry.keyVersion === target.keyVersion,
    )
  )
    history.push(target);
  const body = {
    schemaVersion: 1 as const,
    bindingRevision: revision,
    keySets: [
      {
        reference: binding.keyReference,
        mappings: binding.variables,
        currentWrappingVersion: target.keyVersion,
        wrappingVersions: history,
        indexVersion: proof.to.index.version as string,
        controlVersion: proof.to.control.version as string,
      },
    ],
    secrets: [],
  };
  return parseSnapshotRequest({ ...body, bindingDigest: bindingDigest(body) });
}
export interface TenantControllerOptions {
  secrets: ExplorerSecrets;
  client: MongoClient;
  database: string;
  wrappingKey: Buffer;
  bindings: SecretKeyBinding[];
  runtimeFactory?: typeof createApplicationRuntime<RuntimeSnapshot>;
  legacyFactory?: () => SecretsRuntime;
  fetch?: typeof globalThis.fetch;
  rotationStatus?: (identity: TenantSecretIdentity) => Promise<unknown>;
}
/** One finite controller per database-owned tenant. No request can discover a scope. */
export async function createTenantControllers(
  options: TenantControllerOptions,
) {
  const { secrets, client, database } = options,
    environment = secrets.environment;
  const openLegacy = () =>
    options.legacyFactory?.() ?? createSecretsRuntime({ environment });
  const legacy = openLegacy();
  const create =
    options.runtimeFactory ?? createApplicationRuntime<RuntimeSnapshot>;
  const controllers = new Map<string, ApplicationRuntime<RuntimeSnapshot>>();
  const bindings = new Map(
    options.bindings.map((binding) => [
      `${binding.environment}/${binding.tenantId}`,
      binding,
    ]),
  );
  let closed = false,
    live = false,
    modeUntil = 0,
    timer: ReturnType<typeof setTimeout> | undefined;
  const shared = createApplicationRuntime({
    application: 'explorer-api',
    scope: {
      environment: environment.LOCAL_KEYVAULT_ENVIRONMENT ?? 'development',
      tenant: '_shared',
    },
    environment,
    fetch: options.fetch,
    allowedMappings: processNames,
    prepare: () => {
      throw fail();
    },
  });
  const rootKey = Buffer.from(options.wrappingKey);
  async function authoritative(binding: SecretKeyBinding) {
    const definition = await client
      .db(database)
      .collection('tenantDefinitions')
      .findOne(
        { id: binding.tenantId, environment: binding.environment },
        { maxTimeMS: 3000 },
      );
    if (
      !definition ||
      !Number.isSafeInteger(definition.configRevision) ||
      definition.configRevision < 1 ||
      definition.secretReferences?.key !== binding.keyReference
    )
      throw fail();
    const config = await loadExplorerConfiguration(client, database, rootKey);
    const found = (config.keyBindings.bindings as SecretKeyBinding[]).find(
      (row) =>
        row.environment === binding.environment &&
        row.tenantId === binding.tenantId &&
        row.keyReference === binding.keyReference,
    );
    if (
      !found ||
      roles.some((role) => found.variables[role] !== binding.variables[role])
    )
      throw fail();
    return {
      paused: definition.status === 'in-rotation',
      binding: found,
      identity: {
        environment: found.environment,
        tenantId: found.tenantId,
        configRevision: definition.configRevision as number,
      },
    };
  }
  async function status(identity: TenantSecretIdentity) {
    if (options.rotationStatus) return options.rotationStatus(identity);
    const store = createMongoTenantRotationStore({ client, database });
    if (!store.status) throw fail();
    return store.status({
      environment: identity.environment,
      tenant: identity.tenantId,
    });
  }
  async function startTenant(
    binding: SecretKeyBinding,
    request: RuntimeSnapshotRequest,
  ) {
    const baseline = tenantApplicationDescriptor(binding, request);
    const current = await authoritative(binding);
    const previous = secrets.tenantSnapshot(current.identity);
    async function prepare(snapshot: ApplicationSnapshot, migration = false) {
      const verified = await authoritative(binding);
      if (verified.paused) throw fail();
      const proof = (await status(verified.identity)) as any;
      if (
        migration &&
        !verifiedRotation(
          proof,
          snapshot,
          verified.binding,
          verified.identity.configRevision,
        )
      )
        throw fail();
      let historical = secrets.tenantSnapshot(verified.identity);
      if (proof) {
        // A fresh durable completed record is the sole active-version authority.
        if (proof.stage !== 'completed') throw fail();
        const keys = rotationSnapshotRequest(
          verified.binding,
          proof,
          verified.identity.configRevision,
        );
        const loaded = await legacy.load(snapshot.scope, keys);
        const repeated = (await status(verified.identity)) as any;
        const after = await authoritative(binding);
        if (
          after.identity.configRevision !== verified.identity.configRevision ||
          after.binding.version !== verified.binding.version ||
          !verifiedRotation(
            repeated,
            snapshot,
            after.binding,
            after.identity.configRevision,
          )
        )
          throw fail();
        historical = loaded;
      }
      const value = tenantSnapshotFromApplication(
        verified.binding,
        verified.identity.configRevision,
        snapshot,
        historical,
      );
      return { value };
    }
    let initial;
    if (previous && previous.bindingRevision === request.bindingRevision) {
      initial = {
        snapshot: applicationSnapshotFromTenantLegacy('explorer-api', previous),
        prepared: { value: previous },
      };
    }
    const runtime = create({
      application: 'explorer-api',
      scope: baseline.scope,
      environment,
      fetch: options.fetch,
      allowedMappings: (mapping) =>
        Object.values(binding.variables).includes(mapping) ||
        ['MONGODB_URI', 'CLERK_SECRET_KEY'].includes(mapping) ||
        /^RUNTIME_CREDENTIAL_[A-Z0-9_]{1,100}$/.test(mapping),
      requiredMappings: Object.values(binding.variables),
      ...(initial ? { initial } : { baseline }),
      prepare: (snapshot) => prepare(snapshot),
      prepareMigration: (snapshot) => prepare(snapshot, true),
    });
    if (closed) {
      runtime.close();
      throw fail();
    }
    controllers.set(`${binding.environment}/${binding.tenantId}`, runtime);
    await runtime.start();
  }
  let modePending: Promise<void> | undefined;
  async function discoverMode() {
    if (closed) throw fail();
    if (live || Date.now() < modeUntil) return;
    try {
      live = (await shared.mode()) === 'live';
      modeUntil = Date.now() + 1000;
    } catch (error) {
      if (
        shared.status().reason === 'AccessDenied' ||
        ![...bindings.values()].some((binding) =>
          secrets.tenantSnapshot({
            environment: binding.environment,
            tenantId: binding.tenantId,
            configRevision: 0,
          }),
        )
      )
        throw error;
    }
  }
  function mode() {
    modePending ??= discoverMode().finally(() => {
      modePending = undefined;
    });
    return modePending;
  }
  const tenantPending = new Map<string, Promise<void>>();
  function ensureTenant(id: string): Promise<void> {
    const active = tenantPending.get(id);
    if (active) return active;
    const work = (async () => {
      if (closed) throw fail();
      const existing = controllers.get(id);
      if (existing) {
        await existing.start();
        return;
      }
      const binding = bindings.get(id);
      if (!binding) throw fail();
      if (!legacy.loadTenantBinding) throw fail();
      const entry = await legacy.loadTenantBinding(
        'explorer-api',
        binding.tenantId,
      );
      if (
        closed ||
        !entry ||
        entry.scope.environment !== binding.environment ||
        entry.scope.tenant !== binding.tenantId
      )
        throw fail();
      await startTenant(binding, entry.request);
    })().finally(() => {
      tenantPending.delete(id);
    });
    tenantPending.set(id, work);
    return work;
  }
  async function refresh() {
    await mode();
    if (live)
      await Promise.allSettled(
        [...bindings.keys()].map((id) => ensureTenant(id)),
      );
  }
  try {
    await refresh();
    if (!live)
      await Promise.allSettled(
        [...bindings.values()].map(async (binding) => {
          const current = await authoritative(binding);
          await secrets.initializeTenant(current.identity);
        }),
      );
  } catch (error) {
    shared.close();
    legacy.close();
    rootKey.fill(0);
    for (const runtime of controllers.values()) runtime.close();
    throw error;
  }
  function schedule() {
    if (closed) return;
    timer = setTimeout(() => {
      void refresh()
        .catch(() => {})
        .finally(schedule);
    }, 1000);
    timer.unref?.();
  }
  schedule();
  const middleware: RequestHandler = (request, response, next) => {
    // The controller's PlatformGuard still authenticates this read-only endpoint.
    if (
      request.method === 'GET' &&
      /^\/api\/platform\/tenants\/[^/]+\/[^/]+\/key-rotation\/?$/i.test(
        request.path,
      )
    ) {
      next();
      return;
    }
    // These are existing fixed controller routes; input only selects an already
    // registered finite scope and never creates a binding or reads a new namespace.
    const match =
      /^\/api\/(?:(?:platform|club)\/tenants|onboarding|invitations)\/([^/]+)\/([^/]+)(?:\/|$)/i.exec(
        request.path,
      );
    let id: string | undefined;
    if (match) {
      try {
        const environment = decodeURIComponent(match[1]!),
          tenant = decodeURIComponent(match[2]!);
        if (
          /^[a-z]+$/.test(environment) &&
          /^[a-z0-9][a-z0-9-]{0,63}$/.test(tenant)
        )
          id = `${environment}/${tenant}`;
      } catch {
        /* Express rejects malformed route parameters before service dispatch. */
      }
    }
    if (!id || !bindings.has(id)) {
      next();
      return;
    }
    void (async () => {
      await mode();
      if (live) await ensureTenant(id);
      const runtime = controllers.get(id);
      if (!live) {
        const binding = bindings.get(id)!;
        const snapshot = secrets.tenantSnapshot({
          environment: binding.environment,
          tenantId: binding.tenantId,
          configRevision: 0,
        });
        if (
          !snapshot ||
          !validTenantSnapshot(snapshot) ||
          (await authoritative(binding)).paused
        )
          throw fail();
        next();
        return;
      }
      if (!runtime) throw fail();
      await runtime.start();
      await runtime.withValue(async (snapshot, context) => {
        if (!validTenantSnapshot(snapshot)) throw fail();
        const binding = bindings.get(id)!;
        const current = await authoritative(binding);
        const activeSet = snapshot.keySets.find(
          (set) => set.reference === current.binding.keyReference,
        );
        if (
          current.paused ||
          current.identity.configRevision < snapshot.bindingRevision ||
          !activeSet ||
          activeSet.currentWrappingVersion !== current.binding.version
        )
          throw fail();
        const identityBody = {
          schemaVersion: 1 as const,
          bindingRevision: current.identity.configRevision,
          keySets: snapshot.keySets.map((set) => ({
            reference: set.reference,
            mappings: set.mappings,
            currentWrappingVersion: set.currentWrappingVersion,
            wrappingVersions: set.wrappingVersions.map(
              ({ keyVersion, vaultVersion }) => ({ keyVersion, vaultVersion }),
            ),
            indexVersion: set.index.vaultVersion,
            controlVersion: set.control.vaultVersion,
          })),
          secrets: snapshot.secrets.map(({ mapping, purpose, version }) => ({
            mapping,
            purpose,
            version,
          })),
        };
        const proof = await status(current.identity);
        const currentDescriptor = tenantApplicationDescriptor(current.binding, {
          ...identityBody,
          bindingDigest: bindingDigest(identityBody),
        });
        if (
          proof &&
          !verifiedRotation(
            proof,
            currentDescriptor,
            current.binding,
            current.identity.configRevision,
          )
        )
          throw fail();
        secrets.installTenantSnapshot(current.identity, {
          ...snapshot,
          bindingRevision: current.identity.configRevision,
          bindingDigest: bindingDigest(identityBody),
        });
        await new Promise<void>((resolve) => {
          const finish = () => {
            response.off('finish', finish);
            response.off('close', finish);
            context.signal.removeEventListener('abort', abort);
            resolve();
          };
          const abort = () => {
            response.destroy();
            finish();
          };
          response.once('finish', finish);
          response.once('close', finish);
          context.signal.addEventListener('abort', abort, { once: true });
          if (context.signal.aborted) abort();
          else next();
        });
      });
    })().catch(() => {
      if (response.headersSent) response.destroy();
      else response.status(503).json({ error: 'Tenant secrets unavailable' });
    });
  };
  return {
    middleware,
    rotationStatus: (environment: string, id: string) =>
      status({ environment, tenantId: id, configRevision: 0 }),
    refresh,
    close() {
      if (closed) return;
      closed = true;
      clearTimeout(timer);
      shared.close();
      legacy.close();
      for (const runtime of controllers.values()) runtime.close();
      rootKey.fill(0);
    },
  };
}
