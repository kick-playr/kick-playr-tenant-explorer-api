'use strict';
const { createHash, randomUUID } = require('node:crypto');
const failure = () => Error('Tenant key rotation unavailable');
const check = (value) => {
  if (!value) throw failure();
};
const roles = ['wrapping', 'index', 'control'];
const canonical = (value) =>
  JSON.stringify(value, (_key, item) =>
    item && typeof item === 'object' && !Array.isArray(item)
      ? Object.fromEntries(
          Object.entries(item).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
        )
      : item,
  );
const digest = (value) =>
  createHash('sha256').update(canonical(value)).digest('hex');
function object(value, fields) {
  check(
    value &&
      typeof value === 'object' &&
      !Array.isArray(value) &&
      [Object.prototype, null].includes(Object.getPrototypeOf(value)),
  );
  check(
    Reflect.ownKeys(value).every(
      (k) =>
        typeof k === 'string' &&
        fields.includes(k) &&
        Object.hasOwn(Object.getOwnPropertyDescriptor(value, k), 'value'),
    ),
  );
  return value;
}
function plan(input) {
  const p = object(input, [
    'scope',
    'expectedRevision',
    'fromDigest',
    'toDigest',
    'from',
    'to',
    'wrappingHistory',
    'dataset',
  ]);
  const s = object(p.scope, ['environment', 'tenant']);
  check(
    ['development', 'dev', 'test'].includes(s.environment) &&
      typeof s.tenant === 'string' &&
      /^[A-Za-z0-9_-]{1,64}$/.test(s.tenant) &&
      s.tenant !== '_shared',
  );
  check(Number.isSafeInteger(p.expectedRevision) && p.expectedRevision > 0);
  check(
    /^[a-f0-9]{64}$/.test(p.fromDigest) &&
      /^[a-f0-9]{64}$/.test(p.toDigest) &&
      p.fromDigest !== p.toDigest,
  );
  for (const side of ['from', 'to']) {
    const set = object(p[side], roles);
    check(Object.keys(set).length === 3);
    for (const role of roles) {
      const key = object(set[role], ['name', 'version']);
      check(
        typeof key.name === 'string' &&
          /^[A-Za-z0-9-]{1,127}$/.test(key.name) &&
          typeof key.version === 'string' &&
          /^[a-f0-9]{32}$/.test(key.version),
      );
    }
    check(new Set(roles.map((r) => set[r].name)).size === 3);
  }
  check(
    p.fromDigest === rotationKeyDigest(p.scope, p.from) &&
      p.toDigest === rotationKeyDigest(p.scope, p.to),
  );
  if (p.wrappingHistory !== undefined) {
    check(Array.isArray(p.wrappingHistory) && p.wrappingHistory.length <= 100);
    const aliases = new Set();
    for (const row of p.wrappingHistory) {
      object(row, ['keyVersion', 'name', 'version']);
      check(
        typeof row.keyVersion === 'string' &&
          /^[A-Za-z0-9_.:-]{1,64}$/.test(row.keyVersion) &&
          !aliases.has(row.keyVersion),
      );
      aliases.add(row.keyVersion);
      check(
        typeof row.name === 'string' &&
          /^[A-Za-z0-9-]{1,127}$/.test(row.name) &&
          typeof row.version === 'string' &&
          /^[a-f0-9]{32}$/.test(row.version),
      );
    }
  }
  if(p.dataset!==undefined){object(p.dataset,['database','cluster']);check(typeof p.dataset.database==='string'&&/^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$/.test(p.dataset.database)&&!['admin','config','local'].includes(p.dataset.database.toLowerCase())&&typeof p.dataset.cluster==='string'&&/^[a-f0-9]{64}$/.test(p.dataset.cluster));}
  return freeze(JSON.parse(canonical(p)));
}
function rotationKeyDigest(scope, keys) {
  return digest([
    scope,
    roles.map((role) => [role, keys[role].name, keys[role].version]),
  ]);
}
exports.rotationKeyDigest = rotationKeyDigest;
function rotationId(p) {
  return digest([p.scope, p.fromDigest, p.toDigest]);
}
function freeze(value) {
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}
function publicStatus(job) {
  return freeze(
    JSON.parse(
      JSON.stringify({
        operationId: job.id,
        scope: job.plan.scope,
        stage: job.stage,
        fromDigest: job.plan.fromDigest,
        toDigest: job.plan.toDigest,
        to: job.plan.to,
        wrappingKeyVersion: job.plan.to.wrapping.version,
        wrappingHistory: job.plan.wrappingHistory ?? [],
        completed: job.completed ?? 0,
        ...(Number.isSafeInteger(job.total) ? { total: job.total } : {}),
        ...(Number.isSafeInteger(job.waitUntil)
          ? { waitUntil: job.waitUntil }
          : {}),
        ...(Number.isSafeInteger(job.activatedRevision)
          ? { activatedRevision: job.activatedRevision }
          : {}),
      }),
    ),
  );
}
function createTenantRotationCoordinator({
  store,
  worker,
  leaseMs = 30000,
  batchSize = 100,
}) {
  check(
    Number.isSafeInteger(leaseMs) &&
      leaseMs >= 3000 &&
      leaseMs <= 300000 &&
      Number.isSafeInteger(batchSize) &&
      batchSize >= 1 &&
      batchSize <= 500,
  );
  const pending = new Map();
  function run(input, options = {}) {
    let p;
    try {
      p = plan(input);
    } catch {
      return Promise.reject(failure());
    }
    const id = rotationId(p);
    if (pending.has(id)) return pending.get(id);
    const task = execute(p, options).finally(() => pending.delete(id));
    pending.set(id, task);
    return task;
  }
  async function execute(p, { signal, onProgress } = {}) {
    let lease,
      timer,
      renewing = false;
    const abort = new AbortController();
    const abortParent = () => abort.abort();
    signal?.addEventListener('abort', abortParent, { once: true });
    if (signal?.aborted) abort.abort();
    const active = () => {
      check(!abort.signal.aborted);
    };
    const emit = (job) => {
      try {
        onProgress?.(publicStatus(job));
      } catch {}
    };
    try {
      active();
      let job = await store.begin(p);
      check(canonical(job.plan) === canonical(p));
      if (job.stage === 'completed') {
        emit(job);
        return publicStatus(job);
      }
      job = await store.acquire(job.id, randomUUID(), leaseMs);
      lease = { id: job.id, owner: job.owner, epoch: job.epoch };
      const assertLease = async () => {
        active();
        await store.assertLease(lease);
        active();
      };
      timer = setInterval(
        () => {
          if (renewing) return;
          renewing = true;
          Promise.resolve(store.renew(lease, leaseMs))
            .catch(() => abort.abort())
            .finally(() => {
              renewing = false;
            });
        },
        Math.floor(leaseMs / 3),
      );
      timer.unref?.();
      await assertLease();
      const inventory = await worker.inventory(p, {
        signal: abort.signal,
        assertLease,
        lease: Object.freeze({ ...lease }),
        withWriteFence: (work) => store.withLease(lease, work),
      });
      active();
      check(
        inventory &&
          Array.isArray(inventory.units) &&
          inventory.units.length <= 512 &&
          new Set(inventory.units).size === inventory.units.length &&
          inventory.units.every(
            (u) => typeof u === 'string' && /^[A-Za-z0-9_.:-]{1,128}$/.test(u),
          ),
      );
      check(
        Array.isArray(inventory.roles) &&
          canonical([...inventory.roles].sort()) ===
            canonical([...roles].sort()),
      );
      const inventoryDigest = digest(inventory.units);
      check(!job.inventoryDigest || job.inventoryDigest === inventoryDigest);
      job = await store.checkpoint(lease, {
        stage: 'migrating',
        inventoryDigest,
        ...(Number.isSafeInteger(inventory.total) && inventory.total >= 0
          ? { total: inventory.total }
          : {}),
      });
      emit(job);
      while (job.unit < inventory.units.length) {
        await assertLease();
        const result = await worker.migrateBatch(p, {
          unit: inventory.units[job.unit],
          checkpoint: job.checkpoint ?? null,
          limit: batchSize,
          signal: abort.signal,
          assertLease,
          lease: Object.freeze({ ...lease }),
          withWriteFence: (work) => store.withLease(lease, work),
        });
        active();
        check(
          result &&
            typeof result.done === 'boolean' &&
            Number.isSafeInteger(result.completed) &&
            result.completed >= 0 &&
            result.completed <= batchSize,
        );
        check(
          result.checkpoint === null ||
            (typeof result.checkpoint === 'string' &&
              result.checkpoint.length <= 1024),
        );
        if (result.waitUntil !== undefined) {
          check(
            !result.done &&
              result.completed === 0 &&
              Number.isSafeInteger(result.waitUntil) &&
              result.waitUntil > Date.now() &&
              result.waitUntil <= Date.now() + 86400000,
          );
          await assertLease();
          job = await store.checkpoint(lease, {
            stage: 'waiting-expiry',
            waitUntil: result.waitUntil,
          });
          emit(job);
          while (Date.now() < result.waitUntil) {
            active();
            await new Promise((resolve, reject) => {
              const stop = () => {
                clearTimeout(timer);
                reject(failure());
              };
              const timer = setTimeout(
                () => {
                  abort.signal.removeEventListener('abort', stop);
                  resolve();
                },
                Math.min(1000, result.waitUntil - Date.now()),
              );
              abort.signal.addEventListener('abort', stop, { once: true });
              if (abort.signal.aborted) stop();
            });
          }
          continue;
        }
        check(
          result.done ||
            (result.checkpoint !== null &&
              result.checkpoint !== job.checkpoint),
        );
        await assertLease();
        job = await store.checkpoint(lease, {
          stage: 'migrating',
          unit: job.unit + (result.done ? 1 : 0),
          checkpoint: result.done ? null : result.checkpoint,
          completed: job.completed + result.completed,
        });
        emit(job);
      }
      await assertLease();
      job = await store.checkpoint(lease, { stage: 'verifying' });
      emit(job);
      await worker.verify(p, {
        signal: abort.signal,
        assertLease,
        lease: Object.freeze({ ...lease }),
        withWriteFence: (work) => store.withLease(lease, work),
      });
      await assertLease();
      job = await store.checkpoint(lease, { stage: 'activating' });
      emit(job);
      job = await store.complete(lease, async (session) => {
        const context = {
          session,
          signal: abort.signal,
          assertLease,
          lease: Object.freeze({ ...lease }),
          withWriteFence: (work) => store.withLease(lease, work),
        };
        const revision = await worker.activate(p, context);
        await worker.verifyActivation(p, { ...context, revision });
        active();
        return revision;
      });
      emit(job);
      return publicStatus(job);
    } catch {
      if (lease)
        try {
          await store.fail(lease, 'MigrationFailed');
        } catch {}
      throw failure();
    } finally {
      clearInterval(timer);
      signal?.removeEventListener('abort', abortParent);
    }
  }
  return Object.freeze({ run });
}
exports.createTenantRotationCoordinator = createTenantRotationCoordinator;
exports.rotationId = rotationId;
exports.rotationStatus = publicStatus;
exports.validateRotationPlan = plan;

/** Fixed control database only. No caller-selected collection, database or URI. */
function createMongoTenantRotationStore({
  client,
  database,
  clock = Date.now,
}) {
  check(
    client &&
      typeof client.startSession === 'function' &&
      typeof client.db === 'function' &&
      typeof database === 'string' &&
      /^[A-Za-z0-9_-]{1,63}$/.test(database),
  );
  const db = client.db(database),
    jobs = db.collection('tenantKeyRotations'),
    history = db.collection('tenantKeyRotationHistory'),
    definitions = db.collection('tenantDefinitions'),
    hosts = db.collection('tenantHostBindings'),
    authorities = db.collection('tenantRuntimeAuthorities');
  const key = (scope) => digest(['tenant-key-rotation', scope]);
  const query = (lease) => ({
    id: lease.id,
    owner: lease.owner,
    epoch: lease.epoch,
    leaseUntil: { $gt: clock() },
    stage: { $nin: ['completed'] },
  });
  async function transaction(work) {
    const session = client.startSession();
    try {
      return await session.withTransaction(() => work(session), {
        readConcern: { level: 'snapshot' },
        writeConcern: { w: 'majority' },
        readPreference: 'primary',
      });
    } finally {
      await session.endSession();
    }
  }
  async function leased(lease, session) {
    const job = await jobs.findOne(query(lease), {
      ...(session ? { session } : {}),
      maxTimeMS: 3000,
    });
    check(job);
    return job;
  }
  return Object.freeze({
    async begin(input) {
      const p = plan(input),
        id = rotationId(p),
        _id = key(p.scope);
      return transaction(async (session) => {
        const job = await jobs.findOne({ _id }, { session }),
          definition = await definitions.findOne(
            { environment: p.scope.environment, id: p.scope.tenant },
            { session },
          );
        check(definition);
        if (job?.id === id) {
          check(canonical(job.plan) === canonical(p));
          if (job.stage === 'completed')
            check(
              definition.configRevision >= job.activatedRevision &&
                ['active', 'suspended', 'disabled'].includes(definition.status),
            );
          else
            check(
              definition.status === 'in-rotation' &&
                definition.configRevision === p.expectedRevision,
            );
          return job;
        }
        check(
          !job ||
            (job.stage === 'completed' && job.plan.toDigest === p.fromDigest),
        );
        check(
          definition.configRevision === p.expectedRevision &&
            ['active', 'suspended', 'disabled'].includes(definition.status),
        );
        const next = {
          _id,
          id,
          plan: p,
          previousStatus: definition.status,
          stage: 'pending',
          unit: 0,
          completed: 0,
          checkpoint: null,
          epoch: 0,
          leaseUntil: 0,
          createdAt: clock(),
        };
        const paused = await definitions.updateOne(
          {
            environment: p.scope.environment,
            id: p.scope.tenant,
            configRevision: p.expectedRevision,
            status: definition.status,
          },
          { $set: { status: 'in-rotation' } },
          { session },
        );
        check(paused.modifiedCount === 1);
        next.createdAt=clock();
        if (job) {
          await history.updateOne(
            { _id: job.id },
            { $setOnInsert: { ...job, _id: job.id } },
            { session, upsert: true },
          );
          const replaced = await jobs.replaceOne(
            { _id, id: job.id, stage: 'completed' },
            next,
            { session },
          );
          check(replaced.modifiedCount === 1);
        } else await jobs.insertOne(next, { session });
        return next;
      });
    },
    async acquire(id, owner, leaseMs) {
      return transaction(async (session) => {
        const job = await jobs.findOne({ id }, { session });
        check(
          job &&
            job.stage !== 'completed' &&
            (!job.owner || job.leaseUntil <= clock()),
        );
        const updated = await jobs.findOneAndUpdate(
          { _id: job._id, id, epoch: job.epoch, leaseUntil: job.leaseUntil },
          {
            $set: { owner, leaseUntil: clock() + leaseMs },
            $inc: { epoch: 1 },
          },
          { session, returnDocument: 'after' },
        );
        check(updated);
        return updated;
      });
    },
    async withLease(lease, work) {
      return transaction(async (session) => {
        await leased(lease, session);
        const touched = await jobs.updateOne(
          query(lease),
          { $inc: { writeFence: 1 } },
          { session },
        );
        check(touched.matchedCount === 1);
        const result = await work(session);
        await leased(lease, session);
        return result;
      });
    },
    async assertLease(lease) {
      await leased(lease);
    },
    async renew(lease, leaseMs) {
      const result = await jobs.updateOne(query(lease), {
        $set: { leaseUntil: clock() + leaseMs },
      });
      check(result.matchedCount === 1);
    },
    async checkpoint(lease, patch) {
      object(patch, [
        'stage',
        'inventoryDigest',
        'unit',
        'checkpoint',
        'completed',
        'total',
        'waitUntil',
      ]);
      check(
        ['migrating', 'waiting-expiry', 'verifying', 'activating'].includes(
          patch.stage,
        ),
      );
      return transaction(async (session) => {
        const old = await leased(lease, session);
        check(
          patch.unit === undefined ||
            (Number.isSafeInteger(patch.unit) && patch.unit >= old.unit),
        );
        check(
          patch.completed === undefined ||
            (Number.isSafeInteger(patch.completed) &&
              patch.completed >= old.completed),
        );
        const row = await jobs.findOneAndUpdate(
          query(lease),
          { $set: patch },
          { session, returnDocument: 'after' },
        );
        check(row);
        return row;
      });
    },
    async complete(lease, activate) {
      return transaction(async (session) => {
        const job = await leased(lease, session);
        check(job.stage === 'activating');
        const revision = await activate(session);
        check(revision === job.plan.expectedRevision + 1);
        const scope = job.plan.scope;
        const definition = await definitions.findOne(
          { environment: scope.environment, id: scope.tenant },
          { session },
        );
        check(
          definition?.status === 'in-rotation' &&
            definition.configRevision === revision,
        );
        const hostRows = await hosts
            .find(
              { environment: scope.environment, tenantId: scope.tenant },
              { session },
            )
            .toArray(),
          authorityRows = await authorities
            .find(
              { environment: scope.environment, tenantId: scope.tenant },
              { session },
            )
            .toArray();
        check(
          hostRows.length > 0 &&
            authorityRows.length > 0 &&
            [...hostRows, ...authorityRows].every(
              (row) => row.configRevision === revision,
            ),
        );
        const restored = await definitions.updateOne(
          {
            environment: scope.environment,
            id: scope.tenant,
            status: 'in-rotation',
            configRevision: revision,
          },
          { $set: { status: job.previousStatus } },
          { session },
        );
        check(restored.modifiedCount === 1);
        const completed = await jobs.findOneAndUpdate(
          query(lease),
          {
            $set: {
              stage: 'completed',
              activatedRevision: revision,
              completedAt: clock(),
              leaseUntil: 0,
            },
            $unset: { owner: '' },
          },
          { session, returnDocument: 'after' },
        );
        check(completed);
        return completed;
      });
    },
    async fail(lease) {
      await jobs.updateOne(query(lease), {
        $set: { stage: 'failed', failure: 'MigrationFailed', leaseUntil: 0 },
        $unset: { owner: '' },
      });
    },
    async status(scope) {
      const s = object(scope, ['environment', 'tenant']);
      check(
        ['development', 'dev', 'test'].includes(s.environment) &&
          typeof s.tenant === 'string' &&
          /^[A-Za-z0-9_-]{1,64}$/.test(s.tenant),
      );
      const row = await jobs.findOne({ _id: key(scope) });
      return row ? publicStatus(row) : null;
    },
  });
}
exports.createMongoTenantRotationStore = createMongoTenantRotationStore;
