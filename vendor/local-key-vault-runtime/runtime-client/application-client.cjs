'use strict';
// Server-only generation holder. Consumer adapters own validation and client construction.
const { createHash } = require('node:crypto');
const unavailable = () => Error('Application runtime unavailable');
const check = (v) => {
  if (!v) throw unavailable();
};
const canonical = (v) =>
  JSON.stringify(v, (_k, x) =>
    x && typeof x === 'object' && !Array.isArray(x)
      ? Object.fromEntries(
          Object.entries(x).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
        )
      : x,
  );
const digest = (v) => createHash('sha256').update(canonical(v)).digest('hex');
const object = (x, required, optional = []) => {
  check(
    x &&
      typeof x === 'object' &&
      !Array.isArray(x) &&
      [Object.prototype, null].includes(Object.getPrototypeOf(x)),
  );
  check(
    required.every((k) => Object.hasOwn(x, k)) &&
      Object.keys(x).every((k) => required.includes(k) || optional.includes(k)),
  );
  return x;
};
const text = (x, pattern) => {
  check(typeof x === 'string' && pattern.test(x));
  return x;
};
const envName = (x) => {
  text(x, /^[A-Z][A-Z0-9_]{0,127}$/);
  check(
    !/^(PUBLIC_|NEXT_PUBLIC_|VITE_|NUXT_PUBLIC_|REACT_APP_|NODE_|NPM_|VAULT_|LOCAL_KEYVAULT_)/.test(
      x,
    ) &&
      ![
        'SECRETS_KEYS_STRATEGY',
        'PATH',
        'HOME',
        'SHELL',
        'LD_PRELOAD',
        'LD_LIBRARY_PATH',
        'DYLD_INSERT_LIBRARIES',
        'DYLD_LIBRARY_PATH',
      ].includes(x),
  );
  return x;
};
const freeze = (x) => {
  if (x && typeof x === 'object') {
    Object.values(x).forEach(freeze);
    Object.freeze(x);
  }
  return x;
};
function parseDescriptor(input, scope, application, values = false) {
  const body = object(input, [
    'schemaVersion',
    'application',
    'scope',
    'generation',
    'digest',
    'resources',
  ]);
  const selected = object(body.scope, ['environment', 'tenant']);
  check(
    body.schemaVersion === 2 &&
      body.application === application &&
      selected.environment === scope.environment &&
      selected.tenant === scope.tenant,
  );
  check(
    Number.isSafeInteger(body.generation) &&
      body.generation >= 0 &&
      Array.isArray(body.resources) &&
      body.resources.length > 0 &&
      body.resources.length <= 100,
  );
  const seen = new Set(),
    names = new Set();
  const resources = body.resources.map((raw) => {
    const r = object(raw, [
      'kind',
      'name',
      'mapping',
      'policy',
      'version',
      'classification',
      'attributes',
      ...(values ? ['value'] : []),
    ]);
    check(r.kind === 'secrets');
    text(r.name, /^[A-Za-z0-9-]{1,127}$/);
    envName(r.mapping);
    text(r.version, /^[a-f0-9]{32}$/);
    check(r.policy === 'latest' || r.policy === r.version);
    check(
      ['secret', 'encryption-key', 'managed-credential'].includes(
        r.classification,
      ),
    );
    check(!seen.has(r.mapping) && !names.has(r.name));
    seen.add(r.mapping);
    names.add(r.name);
    const a = object(
      r.attributes,
      ['enabled', 'created', 'updated', 'recoveryLevel'],
      ['nbf', 'exp'],
    );
    check(a.enabled === true && a.recoveryLevel === 'Purgeable');
    for (const k of ['created', 'updated', 'nbf', 'exp'])
      if (a[k] !== undefined) check(Number.isSafeInteger(a[k]) && a[k] >= 0);
    check(a.nbf === undefined || a.exp === undefined || a.nbf < a.exp);
    if (values)
      check(
        typeof r.value === 'string' &&
          Buffer.byteLength(r.value) <= 25600 &&
          !r.value.includes('\0'),
      );
    return {
      kind: r.kind,
      name: r.name,
      mapping: r.mapping,
      policy: r.policy,
      version: r.version,
      classification: r.classification,
      attributes: { ...a },
      ...(values ? { value: r.value } : {}),
    };
  });
  resources.sort((a, b) =>
    a.mapping < b.mapping ? -1 : a.mapping > b.mapping ? 1 : 0,
  );
  const metadata = resources.map(({ value, ...r }) => r);
  const identity = {
    schemaVersion: 2,
    application,
    scope: { ...scope },
    resources: metadata,
  };
  text(body.digest, /^[a-f0-9]{64}$/);
  check(body.digest === digest(identity));
  return freeze({
    ...identity,
    generation: body.generation,
    digest: body.digest,
    resources,
  });
}
function createApplicationRuntime(options) {
  check(typeof window === 'undefined');
  const env = { ...options.environment };
  check(
    ['development', 'test'].includes(env.NODE_ENV) &&
      env.SECRETS_KEYS_STRATEGY === 'LOCAL_KEYVAULT' &&
      env.VERCEL === undefined &&
      env.AWS_LAMBDA_FUNCTION_NAME === undefined &&
      !['PROD', 'production'].includes(env.STAGE),
  );
  const application = text(options.application, /^[a-z][a-z0-9-]{0,63}$/),
    scope = { ...object(options.scope, ['environment', 'tenant']) };
  check(['development', 'dev', 'test'].includes(scope.environment));
  text(scope.tenant, /^(?:[A-Za-z0-9][A-Za-z0-9_-]{0,63}|_shared)$/);
  const url = new URL(env.LOCAL_KEYVAULT_URL ?? 'http://127.0.0.1:4000');
  check(
    url.protocol === 'http:' &&
      url.hostname === '127.0.0.1' &&
      url.pathname === '/' &&
      !url.search &&
      !url.hash &&
      !url.username &&
      !url.password,
  );
  let allowed;
  if (typeof options.allowedMappings === 'function')
    allowed = (name) => options.allowedMappings(name) === true;
  else {
    check(
      Array.isArray(options.allowedMappings) &&
        options.allowedMappings.length <= 256 &&
        new Set(options.allowedMappings).size ===
          options.allowedMappings.length,
    );
    const policy = [...options.allowedMappings];
    policy.forEach(envName);
    allowed = (name) => policy.includes(name);
  }
  const required = [...(options.requiredMappings ?? [])];
  required.forEach(envName);
  check(required.every(allowed) && typeof options.prepare === 'function');
  const interval = options.intervalMs ?? 1000;
  check(Number.isSafeInteger(interval) && interval >= 250 && interval <= 5000);
  const operationTimeout = options.operationTimeoutMs ?? 30000;
  check(
    Number.isSafeInteger(operationTimeout) &&
      operationTimeout > 0 &&
      operationTimeout <= 300000,
  );
  const applicationToken=env.LOCAL_KEYVAULT_APPLICATION_TOKEN;
  if(applicationToken!==undefined)text(applicationToken,/^[\x21-\x7e]{32,4096}$/);
  let tokenSupplier = applicationToken ? ()=>applicationToken : options.credentialSupplier;
  if (!tokenSupplier) {
    check(
      typeof env.LOCAL_KEYVAULT_AUTH_JSON === 'string' &&
        Buffer.byteLength(env.LOCAL_KEYVAULT_AUTH_JSON) <= 131072,
    );
    const auth = object(JSON.parse(env.LOCAL_KEYVAULT_AUTH_JSON), [
      'schemaVersion',
      'grants',
    ]);
    check(
      auth.schemaVersion === 1 &&
        Array.isArray(auth.grants) &&
        auth.grants.length <= 64,
    );
    const grants = auth.grants.filter(
      (g) => g?.environment === scope.environment && g?.tenant === scope.tenant,
    );
    check(grants.length === 1);
    const token = text(grants[0].token, /^[\x21-\x7e]{32,4096}$/);
    tokenSupplier = () => token;
  }
  check(typeof tokenSupplier === 'function');
  const abort = new AbortController(),
    fetcher = options.fetch ?? globalThis.fetch,
    retired = new Set();
  let failures = 0,
    migrationBaseline,
    migrationRecoveryRequired = false;
  let closed = false,
    running = false,
    pending,
    scheduled,
    instance,
    current,
    state = 'starting',
    reason,
    generation;
  async function request(action, body) {
    const deadline = new AbortController();
    const timer = setTimeout(() => deadline.abort(), 5000);
    timer.unref?.();
    try {
      return await performRequest(
        action,
        body,
        AbortSignal.any([abort.signal, deadline.signal]),
      );
    } finally {
      clearTimeout(timer);
    }
  }
  async function performRequest(action, body, signal) {
    if (closed) throw unavailable();
    const token = await abortable(
      Promise.resolve().then(() => tokenSupplier(Object.freeze({ ...scope }))),
      signal,
    );
    text(token, /^[\x21-\x7e]{32,4096}$/);
    let response;
    try {
      response = await abortable(
        fetcher(
          url.origin +
            (applicationToken ? '/local/runtime-access/'+application+'/application-runtime/' : '/local/application-runtime/') +
            application +
            '/' +
            action,
          {
            method: ['desired', 'mode'].includes(action) ? 'GET' : 'POST',
            headers: {
              Authorization: 'Bearer ' + token,
              'Content-Type': 'application/json',
              'x-vault-environment': scope.environment,
              'x-vault-tenant': scope.tenant,
            },
            ...(body === undefined ? {} : { body: JSON.stringify(body) }),
            redirect: 'error',
            cache: 'no-store',
            signal,
          },
        ),
        signal,
      );
    } catch {
      throw { kind: 'unavailable' };
    }
    if (!response.ok) {
      void response.body?.cancel().catch(() => {});
      throw {
        kind:
          ([401, 403].includes(response.status) && action !== 'acknowledge') ||
          (action === 'in-use' && response.status === 404)
            ? 'denied'
            : action === 'acknowledge'
              ? 'report'
              : 'unavailable',
      };
    }
    check(response.headers.get('content-type')?.includes('application/json'));
    const reader = response.body?.getReader();
    check(reader);
    const parts = [];
    let size = 0;
    try {
      for (;;) {
        const p = await abortable(reader.read(), signal);
        if (p.done) break;
        size += p.value.length;
        check(size <= (action === 'snapshot' ? 4 * 1024 * 1024 : 65536));
        parts.push(Buffer.from(p.value));
      }
    } finally {
      void reader.cancel().catch(() => {});
    }
    if (closed) throw unavailable();
    return JSON.parse(Buffer.concat(parts).toString('utf8'));
  }
  function valid(record) {
    return record && record.expiresAt > Date.now();
  }
  function expire(record) {
    clearTimeout(record.expiryTimer);
    if (record.expiresAt === Infinity) return;
    if (record.expiresAt > Date.now()) {
      record.expiryTimer = setTimeout(
        () => expire(record),
        Math.min(record.expiresAt - Date.now(), 2147483647),
      );
      record.expiryTimer.unref?.();
      return;
    }
    for (const c of record.operations) c.abort();
    if (current === record) {
      state = 'blocked';
      reason = 'InUseExpired';
    }
  }
  async function dispose(record) {
    if (!record || record.disposed || record.refs) return;
    record.disposed = true;
    clearTimeout(record.expiryTimer);
    retired.delete(record);
    try {
      await record.prepared.dispose?.();
    } catch {
      /* Disposal errors cannot expose adapter payloads. */
    }
  }
  function retire(record) {
    if (!record) return;
    record.retired = true;
    retired.add(record);
    void dispose(record);
  }
  function deny() {
    state = 'blocked';
    reason = 'AccessDenied';
    const old = current;
    current = undefined;
    if (old) for (const c of old.operations) c.abort();
    retire(old);
  }
  function checkSnapshot(snapshot) {
    check(
      snapshot.resources.every((r) => allowed(r.mapping)) &&
        required.every((n) => snapshot.resources.some((r) => r.mapping === n)),
    );
    const now = Math.floor(Date.now() / 1000);
    check(
      snapshot.resources.every(
        (r) =>
          (r.attributes.exp === undefined || r.attributes.exp > now) &&
          (r.attributes.nbf === undefined || r.attributes.nbf <= now),
      ),
    );
  }
  function needsMigration(next) {
    if (migrationRecoveryRequired) return true;
    if (migrationBaseline === undefined) return false;
    const before = migrationBaseline.resources.filter(
        (r) => r.classification !== 'secret',
      ),
      after = next.resources.filter((r) => r.classification !== 'secret');
    return (
      canonical(
        before.map((r) => [r.name, r.mapping, r.version, r.classification]),
      ) !==
      canonical(
        after.map((r) => [r.name, r.mapping, r.version, r.classification]),
      )
    );
  }
  function managedOnly(next) {
    if (
      migrationRecoveryRequired ||
      !migrationBaseline ||
      typeof options.prepareManagedCredential !== 'function'
    )
      return false;
    const encryption = (descriptor) =>
      canonical(
        descriptor.resources
          .filter((r) => r.classification === 'encryption-key')
          .map((r) => [r.name, r.mapping, r.version, r.classification]),
      );
    return (
      needsMigration(next) && encryption(migrationBaseline) === encryption(next)
    );
  }
  async function report() {
    if (!instance) {
      const r = object(await request('register', {}), [
        'instanceId',
        'proof',
        'expiresAt',
      ]);
      text(r.instanceId, /^[a-f0-9-]{36}$/);
      text(r.proof, /^[A-Za-z0-9_-]{43}$/);
      check(Number.isSafeInteger(r.expiresAt) && r.expiresAt > Date.now());
      instance = r;
    }
    const retained = current?.snapshot ?? migrationBaseline;
    if (!retained) return;
    const r = object(
      await request('acknowledge', {
        instanceId: instance.instanceId,
        proof: instance.proof,
        generation: retained.generation,
        digest: retained.digest,
        status:
          reason === 'MigrationInProgress'
            ? 'updating'
            : state === 'applied'
              ? 'applied'
              : state === 'blocked'
                ? 'blocked'
                : 'warning',
      }),
      ['accepted', 'expiresAt'],
    );
    check(r.accepted === true && Number.isSafeInteger(r.expiresAt));
  }
  async function drain() {
    const records = [...retired, ...(current ? [current] : [])];
    const cleanup = [];
    const waits = records
      .filter((r) => r.refs > 0)
      .map((r) => {
        for (const operation of r.operations) operation.abort();
        return new Promise((resolve) => {
          r.waiters.add(resolve);
          cleanup.push(() => r.waiters.delete(resolve));
        });
      });
    try {
      await abortable(
        Promise.all(waits),
        AbortSignal.any([abort.signal, AbortSignal.timeout(operationTimeout)]),
      );
    } finally {
      cleanup.forEach((fn) => fn());
    }
  }
  async function cycle() {
    let candidate,
      fencing = false;
    try {
      if (current) {
        expire(current);
        if (!valid(current)) {
          state = 'blocked';
          reason = 'InUseExpired';
        }
        await request('in-use', {
          resources: current.snapshot.resources.map((r) => ({
            name: r.name,
            version: r.version,
          })),
        });
      }
      const desired = parseDescriptor(
        await request('desired'),
        scope,
        application,
      );
      checkSnapshot(desired);
      if (
        migrationRecoveryRequired ||
        current?.snapshot.digest !== desired.digest
      ) {
        const snapshot = parseDescriptor(
          await request('snapshot', {
            generation: desired.generation,
            digest: desired.digest,
          }),
          scope,
          application,
          true,
        );
        check(
          snapshot.digest === desired.digest &&
            snapshot.generation === desired.generation,
        );
        checkSnapshot(snapshot);
        if (current?.refs && retired.size >= 32) {
          state = 'warning';
          reason = 'DrainPending';
          try {
            await report();
          } catch {
            instance = undefined;
          }
          return;
        }
        const managedRefresh = managedOnly(snapshot);
        const migration = needsMigration(snapshot) && !managedRefresh;
        if (migration && !options.prepareMigration) {
          state = current ? 'warning' : 'blocked';
          reason = 'MigrationRequired';
          try {
            await report();
          } catch {
            instance = undefined;
          }
          return;
        }
        if (migration) {
          fencing = true;
          state = 'blocked';
          reason = 'MigrationInProgress';
          try {
            await report();
          } catch {
            instance = undefined;
          }
          await drain();
          migrationRecoveryRequired = true;
        }
        const prepare = migration
          ? options.prepareMigration
          : managedRefresh
            ? options.prepareManagedCredential
            : options.prepare;
        candidate = await prepare(snapshot, {
          previous: valid(current) ? current.snapshot : undefined,
          previousDescriptor: migrationBaseline,
          signal: abort.signal,
        });
        check(
          candidate &&
            Object.hasOwn(candidate, 'value') &&
            (candidate.dispose === undefined ||
              typeof candidate.dispose === 'function'),
        );
        if (closed) {
          try {
            await candidate.dispose?.();
          } catch {}
          return;
        }
        checkSnapshot(snapshot);
        const latest = parseDescriptor(
          await request('desired'),
          scope,
          application,
        );
        check(latest.digest === snapshot.digest);
        checkSnapshot(snapshot);
        const record = {
          snapshot,
          prepared: candidate,
          refs: 0,
          operations: new Set(),
          waiters: new Set(),
          expiresAt: Math.min(
            ...snapshot.resources.map((r) =>
              r.attributes.exp === undefined
                ? Infinity
                : r.attributes.exp * 1000,
            ),
          ),
        };
        candidate = undefined;
        const old = current;
        current = record;
        migrationBaseline = freeze({
          ...snapshot,
          resources: snapshot.resources.map(({ value, ...r }) => r),
        });
        generation = snapshot.generation;
        migrationRecoveryRequired = false;
        expire(record);
        retire(old);
      }
      state = 'applied';
      reason = undefined;
      failures = 0;
      try {
        await report();
      } catch (e) {
        instance = undefined;
        if (e?.kind === 'denied') deny();
        else {
          state = 'warning';
          reason = 'ReportUnavailable';
        }
      }
    } catch (e) {
      if (candidate)
        try {
          await candidate.dispose?.();
        } catch {}
      if (closed) return;
      if (e?.kind === 'denied') deny();
      else {
        failures++;
        state =
          migrationRecoveryRequired || fencing
            ? 'blocked'
            : valid(current)
              ? 'warning'
              : 'blocked';
        reason = migrationRecoveryRequired
          ? 'MigrationFailed'
          : fencing
            ? 'DrainPending'
            : valid(current)
              ? 'RefreshFailed'
              : 'SnapshotUnavailable';
        if (current || migrationBaseline)
          try {
            await report();
          } catch (reportError) {
            instance = undefined;
            if (reportError?.kind === 'denied') deny();
          }
      }
    }
  }
  function schedule() {
    if (running && !closed) {
      scheduled = setTimeout(
        async () => {
          await refresh();
          schedule();
        },
        Math.min(5000, interval * Math.pow(2, Math.min(failures, 3))),
      );
      scheduled.unref?.();
    }
  }
  function refresh() {
    if (closed) return Promise.reject(unavailable());
    if (!pending)
      pending = cycle().finally(() => {
        pending = undefined;
      });
    return pending;
  }
  async function start() {
    if (closed) throw unavailable();
    const first = !running;
    if (first) running = true;
    if (first || pending) await refresh();
    if (!current || !valid(current) || state === 'blocked') {
      if (first) running = false;
      throw unavailable();
    }
    if (first) schedule();
  }
  async function withValue(fn) {
    if (
      closed ||
      !running ||
      !valid(current) ||
      state === 'blocked' ||
      current.refs >= 1024
    )
      throw unavailable();
    const record = current,
      c = new AbortController();
    record.refs++;
    record.operations.add(c);
    const timer = setTimeout(() => c.abort(), operationTimeout);
    timer.unref?.();
    try {
      return await fn(
        record.prepared.value,
        Object.freeze({
          signal: AbortSignal.any([c.signal, abort.signal]),
          generation: record.snapshot.generation,
          digest: record.snapshot.digest,
          scope: Object.freeze({ ...scope }),
        }),
      );
    } finally {
      clearTimeout(timer);
      record.operations.delete(c);
      record.refs--;
      if (!record.refs) for (const resolve of record.waiters) resolve();
      if (record.retired) await dispose(record);
    }
  }
  function close() {
    if (closed) return;
    closed = true;
    running = false;
    clearTimeout(scheduled);
    abort.abort();
    const old = current;
    current = undefined;
    retire(old);
    for (const r of retired) {
      for (const c of r.operations) c.abort();
      void dispose(r);
    }
    state = 'closed';
    reason = undefined;
    instance = undefined;
    migrationBaseline = undefined;
  }
  async function mode() {
    try {
      const response = object(await request('mode'), [
        'schemaVersion',
        'application',
        'scope',
        'mode',
      ]);
      check(
        response.schemaVersion === 2 &&
          response.application === application &&
          ['legacy', 'live'].includes(response.mode),
      );
      const selected = object(response.scope, ['environment', 'tenant']);
      check(
        selected.environment === scope.environment &&
          selected.tenant === scope.tenant,
      );
      return response.mode;
    } catch (e) {
      if (e?.kind === 'denied') deny();
      throw unavailable();
    }
  }
  if (options.baseline) {
    check(!options.initial);
    migrationBaseline = parseDescriptor(options.baseline, scope, application);
    check(migrationBaseline.resources.every((r) => allowed(r.mapping)));
  }
  if (options.initial) {
    const initial = object(options.initial, ['snapshot', 'prepared']);
    const snapshot = parseDescriptor(
      initial.snapshot,
      scope,
      application,
      true,
    );
    check(
      snapshot.resources.every((r) => allowed(r.mapping)) &&
        required.every((n) => snapshot.resources.some((r) => r.mapping === n)),
    );
    // A retained expired generation is never admitted, but its key baseline is still needed for safe recovery.
    check(
      initial.prepared &&
        Object.hasOwn(initial.prepared, 'value') &&
        (initial.prepared.dispose === undefined ||
          typeof initial.prepared.dispose === 'function'),
    );
    current = {
      snapshot,
      prepared: initial.prepared,
      refs: 0,
      operations: new Set(),
      waiters: new Set(),
      expiresAt: Math.min(
        ...snapshot.resources.map((r) =>
          r.attributes.exp === undefined ? Infinity : r.attributes.exp * 1000,
        ),
      ),
    };
    migrationBaseline = freeze({
      ...snapshot,
      resources: snapshot.resources.map(({ value, ...r }) => r),
    });
    generation = snapshot.generation;
    expire(current);
  }
  return Object.freeze({
    mode,
    start,
    refresh,
    withValue,
    close,
    status: () =>
      Object.freeze({
        state,
        ...(reason ? { reason } : {}),
        ...(generation === undefined ? {} : { generation }),
        ...(current ? { digest: current.snapshot.digest } : {}),
      }),
  });
}
function abortable(promise, signal) {
  return new Promise((resolve, reject) => {
    let settled = false;
    function finish(fn, value) {
      if (settled) return;
      settled = true;
      signal.removeEventListener('abort', onAbort);
      fn(value);
    }
    function onAbort() {
      finish(reject, unavailable());
    }
    signal.addEventListener('abort', onAbort, { once: true });
    if (signal.aborted) onAbort();
    Promise.resolve(promise).then(
      (value) => finish(resolve, value),
      () => finish(reject, unavailable()),
    );
  });
}
function applicationSnapshotFromLegacy(application, input) {
  const body = object(input, [
    'schemaVersion',
    'environment',
    'tenant',
    'bindingRevision',
    'bindingDigest',
    'generation',
    'loadedAt',
    'keySets',
    'secrets',
  ]);
  check(
    body.schemaVersion === 1 &&
      body.tenant === '_shared' &&
      Array.isArray(body.keySets) &&
      body.keySets.length === 0 &&
      Array.isArray(body.secrets),
  );
  check(
    Number.isSafeInteger(body.generation) &&
      body.generation >= 0 &&
      Number.isSafeInteger(body.loadedAt) &&
      body.loadedAt > 0,
  );
  const selected = { environment: body.environment, tenant: body.tenant };
  check(['development', 'dev', 'test'].includes(selected.environment));
  text(application, /^[a-z][a-z0-9-]{0,63}$/);
  require('./index.cjs').parseSnapshotRequest({
    schemaVersion: 1,
    bindingRevision: body.bindingRevision,
    bindingDigest: body.bindingDigest,
    keySets: [],
    secrets: body.secrets.map((s) => ({
      mapping: s.mapping,
      purpose: s.purpose,
      version: s.version,
    })),
  });
  const resources = body.secrets
    .map((raw) => {
      const r = object(raw, [
        'mapping',
        'purpose',
        'version',
        'value',
        'attributes',
      ]);
      const name =
        'kv-' +
        createHash('sha256')
          .update(
            JSON.stringify([
              selected.environment,
              selected.tenant,
              'secret',
              r.purpose,
            ]),
          )
          .digest('hex');
      return {
        kind: 'secrets',
        name,
        mapping: r.mapping,
        policy: r.version,
        version: r.version,
        classification:
          /(?:WRAPPING_KEY_V[0-9]+|INDEX_KEY|CONTROL_KEY|CREDENTIAL_KEY|ENCRYPTION_KEY|MANAGER_INVITATION_FLOW_KEY)$/.test(
            r.mapping,
          )
            ? 'encryption-key'
            : 'secret',
        attributes: { ...r.attributes },
        value: r.value,
      };
    })
    .sort((a, b) =>
      a.mapping < b.mapping ? -1 : a.mapping > b.mapping ? 1 : 0,
    );
  const identity = {
    schemaVersion: 2,
    application,
    scope: selected,
    resources: resources.map(({ value, ...r }) => r),
  };
  return parseDescriptor(
    {
      ...identity,
      generation: body.generation,
      digest: digest(identity),
      resources,
    },
    selected,
    application,
    true,
  );
}
exports.applicationSnapshotFromLegacy = applicationSnapshotFromLegacy;
exports.createApplicationRuntime = (options) => {
  try {
    return createApplicationRuntime(options);
  } catch {
    throw unavailable();
  }
};
exports.parseApplicationDescriptor = parseDescriptor;

// A manifest carries immutable pins, not a working generation. Neutral attributes here
// are metadata placeholders; this descriptor is only for migration comparison.
function applicationDescriptorFromLegacy(application, scope, input) {
  const request = require('./index.cjs').parseSnapshotRequest(input);
  check(request.keySets.length === 0);
  const snapshot = applicationSnapshotFromLegacy(application, {
    ...request,
    ...scope,
    generation: 0,
    loadedAt: Date.now(),
    secrets: request.secrets.map((s) => ({
      ...s,
      value: 'metadata-placeholder',
      attributes: {
        enabled: true,
        created: 0,
        updated: 0,
        recoveryLevel: 'Purgeable',
      },
    })),
  });
  return freeze({
    ...snapshot,
    resources: snapshot.resources.map(({ value, ...resource }) => resource),
  });
}
exports.applicationDescriptorFromLegacy = applicationDescriptorFromLegacy;

function tenantLegacy(application, selected, request, snapshot) {
  check(['club-api', 'explorer-api'].includes(application));
  check(
    selected &&
      ['development', 'dev', 'test'].includes(selected.environment) &&
      typeof selected.tenant === 'string' &&
      /^[A-Za-z0-9_-]{1,64}$/.test(selected.tenant) &&
      selected.tenant !== '_shared',
  );
  request = require('./index.cjs').parseSnapshotRequest(request);
  const neutral = {
    enabled: true,
    created: 0,
    updated: 0,
    recoveryLevel: 'Purgeable',
  };
  const name = (kind, purpose) =>
    'kv-' +
    createHash('sha256')
      .update(
        JSON.stringify([selected.environment, selected.tenant, kind, purpose]),
      )
      .digest('hex');
  const resources = request.secrets.map((secret) => {
    const value = snapshot?.secrets.find(
      (s) =>
        s.mapping === secret.mapping &&
        s.purpose === secret.purpose &&
        s.version === secret.version,
    );
    check(!snapshot || value);
    return {
      kind: 'secrets',
      name: name('secret', secret.purpose),
      mapping: secret.mapping,
      policy: secret.version,
      version: secret.version,
      classification:
        application === 'club-api' &&
        /^RUNTIME_CREDENTIAL_[A-Z0-9_]{1,100}$/.test(secret.mapping)
          ? 'managed-credential'
          : 'secret',
      attributes: value?.attributes ?? neutral,
      ...(snapshot ? { value: value.value } : {}),
    };
  });
  for (const set of request.keySets) {
    const match = /^([a-z0-9]+(?:-[a-z0-9]+)*):([^:]+):key$/.exec(
      set.reference,
    );
    check(match && match[1].length <= 48 && match[2] === selected.tenant);
    const actual = snapshot?.keySets.find((k) => k.reference === set.reference);
    check(!snapshot || actual);
    const wrap = set.wrappingVersions.find(
      (w) => w.keyVersion === set.currentWrappingVersion,
    );
    check(wrap);
    for (const role of ['wrapping', 'index', 'control']) {
      const path = role === 'wrapping' ? 'wrapping/v1' : role;
      const version =
        role === 'wrapping'
          ? wrap.vaultVersion
          : role === 'index'
            ? set.indexVersion
            : set.controlVersion;
      const value =
        role === 'wrapping'
          ? actual?.wrappingVersions.find(
              (w) =>
                w.keyVersion === set.currentWrappingVersion &&
                w.vaultVersion === version,
            )
          : actual?.[role];
      check(!snapshot || (value && value.vaultVersion === version));
      resources.push({
        kind: 'secrets',
        name:
          `tk-${role}-` +
          createHash('sha256')
            .update(
              JSON.stringify([
                selected.environment,
                selected.tenant,
                set.reference,
                path,
              ]),
            )
            .digest('hex'),
        mapping: set.mappings[role],
        policy: version,
        version,
        classification: 'encryption-key',
        attributes: value?.attributes ?? neutral,
        ...(snapshot ? { value: value.value } : {}),
      });
    }
  }
  resources.sort((a, b) =>
    a.mapping < b.mapping ? -1 : a.mapping > b.mapping ? 1 : 0,
  );
  const identity = {
    schemaVersion: 2,
    application,
    scope: { ...selected },
    resources: resources.map(({ value, ...r }) => r),
  };
  const descriptor = {
    ...identity,
    generation: snapshot?.generation ?? 0,
    digest: digest(identity),
    resources,
  };
  return parseDescriptor(descriptor, selected, application, !!snapshot);
}
function applicationDescriptorFromTenantLegacy(application, scope, request) {
  return tenantLegacy(application, scope, request);
}
function applicationSnapshotFromTenantLegacy(application, input) {
  check(input?.schemaVersion === 1);
  const keySets = input.keySets.map((k) => ({
    reference: k.reference,
    mappings: k.mappings,
    currentWrappingVersion: k.currentWrappingVersion,
    wrappingVersions: k.wrappingVersions.map((w) => ({
      keyVersion: w.keyVersion,
      vaultVersion: w.vaultVersion,
    })),
    indexVersion: k.index.vaultVersion,
    controlVersion: k.control.vaultVersion,
  }));
  const request = {
    schemaVersion: 1,
    bindingRevision: input.bindingRevision,
    bindingDigest: input.bindingDigest,
    keySets,
    secrets: input.secrets.map((s) => ({
      mapping: s.mapping,
      purpose: s.purpose,
      version: s.version,
    })),
  };
  return tenantLegacy(
    application,
    { environment: input.environment, tenant: input.tenant },
    request,
    input,
  );
}
exports.applicationDescriptorFromTenantLegacy =
  applicationDescriptorFromTenantLegacy;
exports.applicationSnapshotFromTenantLegacy =
  applicationSnapshotFromTenantLegacy;
