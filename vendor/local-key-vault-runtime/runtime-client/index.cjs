'use strict';
// Server-only; intentionally independent of Nest and of the vault's unseal credentials.
const { createHash } = require('node:crypto');
const unavailable = () => Error('Secrets configuration unavailable');
const check = condition => { if (!condition) throw unavailable(); };
const own = (value, key) => Object.hasOwn(value, key);
function object(input, fields) {
  check(input !== null && typeof input === 'object' && !Array.isArray(input) && [Object.prototype, null].includes(Object.getPrototypeOf(input)));
  check(Object.keys(input).length === fields.length && fields.every(key => own(input, key)));
  return input;
}
const part = value => { check(typeof value === 'string' && /^(?:[A-Za-z0-9][A-Za-z0-9_-]{0,63}|_shared)$/.test(value)); return value; };
function scope(input) { const s = object(input, ['environment', 'tenant']); return { environment: part(s.environment), tenant: part(s.tenant) }; }
function mapping(value) {
  check(typeof value === 'string' && /^[A-Z][A-Z0-9_]{0,127}$/.test(value));
  check(!/^(PUBLIC_|NEXT_PUBLIC_|VITE_|NUXT_PUBLIC_|REACT_APP_|NODE_|NPM_|VAULT_|LOCAL_KEYVAULT_)/.test(value));
  check(!['PATH', 'HOME', 'SHELL', 'LD_PRELOAD', 'LD_LIBRARY_PATH', 'DYLD_INSERT_LIBRARIES', 'DYLD_LIBRARY_PATH', 'SECRETS_KEYS_STRATEGY'].includes(value));
  return value;
}
const version = value => { check(typeof value === 'string' && /^[a-f0-9]{32}$/.test(value)); return value; };
const keyVersion = value => { check(typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(value) && value !== 'latest'); return value; };
const compare = (a, b) => a < b ? -1 : a > b ? 1 : 0;
function descriptor(input) {
  const fields = ['schemaVersion', 'bindingRevision', 'keySets', 'secrets'];
  const body = object(input, own(input ?? {}, 'bindingDigest') ? [...fields, 'bindingDigest'] : fields);
  check(body.schemaVersion === 1 && Number.isSafeInteger(body.bindingRevision) && body.bindingRevision > 0);
  check(Array.isArray(body.keySets) && Array.isArray(body.secrets) && body.keySets.length + body.secrets.length > 0 && body.keySets.length <= 100 && body.secrets.length <= 100);
  let count = 0; const mappings = new Set(), refs = new Set(), purposes = new Set();
  const addMapping = value => { const name = mapping(value); check(!mappings.has(name)); mappings.add(name); return name; };
  const keySets = body.keySets.map(raw => {
    const k = object(raw, ['reference', 'mappings', 'wrappingVersions', 'currentWrappingVersion', 'indexVersion', 'controlVersion']);
    check(typeof k.reference === 'string' && /^([a-z0-9]+(?:-[a-z0-9]+)*):([A-Za-z0-9][A-Za-z0-9_-]{0,63}|_shared):key$/.test(k.reference) && k.reference.split(':')[0].length <= 48 && !refs.has(k.reference)); refs.add(k.reference);
    const m = object(k.mappings, ['wrapping', 'index', 'control']);
    const names = { wrapping: addMapping(m.wrapping), index: addMapping(m.index), control: addMapping(m.control) };
    check(Array.isArray(k.wrappingVersions) && k.wrappingVersions.length > 0 && k.wrappingVersions.length <= 100);
    const keys = new Set();
    const wrappingVersions = k.wrappingVersions.map(rawVersion => {
      const v = object(rawVersion, ['keyVersion', 'vaultVersion']); const key = keyVersion(v.keyVersion), pin = version(v.vaultVersion);
      check(!keys.has(key)); keys.add(key);
      return { keyVersion: key, vaultVersion: pin };
    }).sort((a, b) => compare(a.keyVersion, b.keyVersion));
    const current = keyVersion(k.currentWrappingVersion); check(keys.has(current)); count += wrappingVersions.length + 2;
    return { reference: k.reference, mappings: names, wrappingVersions, currentWrappingVersion: current, indexVersion: version(k.indexVersion), controlVersion: version(k.controlVersion) };
  }).sort((a, b) => compare(a.reference, b.reference));
  const secrets = body.secrets.map(raw => {
    const s = object(raw, ['mapping', 'purpose', 'version']);
    check(typeof s.purpose === 'string' && /^[A-Za-z0-9-]{1,127}$/.test(s.purpose) && !purposes.has(s.purpose)); purposes.add(s.purpose); count++;
    return { mapping: addMapping(s.mapping), purpose: s.purpose, version: version(s.version) };
  }).sort((a, b) => compare(a.mapping, b.mapping));
  check(count <= 100);
  return { schemaVersion: 1, bindingRevision: body.bindingRevision, keySets, secrets };
}
function bindingDigest(input) { return createHash('sha256').update(JSON.stringify(descriptor(input))).digest('hex'); }
function parseSnapshotRequest(input) {
  const parsed = descriptor(input); check(typeof input.bindingDigest === 'string' && /^[a-f0-9]{64}$/.test(input.bindingDigest) && input.bindingDigest === bindingDigest(parsed));
  return { ...parsed, bindingDigest: input.bindingDigest };
}
function parseRuntimeManifest(input) {
  const body = object(input, ['schemaVersion', 'application', 'scope', 'request', 'tenants']);
  check(body.schemaVersion === 1 && typeof body.application === 'string' && /^[a-z][a-z0-9-]{0,63}$/.test(body.application));
  const selected = scope(body.scope), request = parseSnapshotRequest(body.request);
  check(['development', 'dev', 'test'].includes(selected.environment));
  for (const key of request.keySets) check(key.reference.split(':')[1] === selected.tenant);
  check(Array.isArray(body.tenants) && body.tenants.length <= 32);
  const seen = new Set();
  const tenants = body.tenants.map(raw => {
    const t = object(raw, ['tenant', 'bindingRevision', 'bindingDigest']), tenant = part(t.tenant);
    check(tenant !== '_shared' && !seen.has(tenant) && Number.isSafeInteger(t.bindingRevision) && t.bindingRevision > 0 && typeof t.bindingDigest === 'string' && /^[a-f0-9]{64}$/.test(t.bindingDigest)); seen.add(tenant);
    return { tenant, bindingRevision: t.bindingRevision, bindingDigest: t.bindingDigest };
  }).sort((a, b) => compare(a.tenant, b.tenant));
  check(selected.tenant === '_shared' ? request.keySets.length === 0 : tenants.length === 0);
  return { schemaVersion: 1, application: body.application, scope: selected, request, tenants };
}
function attributes(input) {
  check(input && typeof input === 'object' && !Array.isArray(input));
  check(Object.keys(input).every(k => ['enabled', 'created', 'updated', 'recoveryLevel', 'nbf', 'exp'].includes(k)));
  check(input.enabled === true && input.recoveryLevel === 'Purgeable');
  for (const k of ['created', 'updated']) check(Number.isSafeInteger(input[k]) && input[k] >= 0);
  const now = Math.floor(Date.now() / 1000);
  for (const k of ['nbf', 'exp']) if (own(input, k)) check(Number.isSafeInteger(input[k]) && input[k] >= 0);
  check(input.nbf === undefined || input.nbf <= now); check(input.exp === undefined || input.exp > now);
  return { ...input };
}
function value(input, expectedVersion, symmetric = false) {
  const v = object(input, ['vaultVersion', 'value', 'attributes']); check(v.vaultVersion === expectedVersion);
  check(typeof v.value === 'string' && Buffer.byteLength(v.value) <= 25600 && !v.value.includes('\0'));
  if (symmetric) { const b = Buffer.from(v.value, 'base64'); check(v.value.length === 44 && b.length === 32 && b.toString('base64') === v.value); }
  return { vaultVersion: v.vaultVersion, value: v.value, attributes: attributes(v.attributes) };
}
function freeze(input) { if (input && typeof input === 'object') { Object.values(input).forEach(freeze); Object.freeze(input); } return input; }
function validateSnapshot(input, selectedScope, request) {
  const s = object(input, ['schemaVersion', 'environment', 'tenant', 'bindingRevision', 'bindingDigest', 'generation', 'loadedAt', 'keySets', 'secrets']);
  check(s.schemaVersion === 1 && s.environment === selectedScope.environment && s.tenant === selectedScope.tenant && s.bindingRevision === request.bindingRevision && s.bindingDigest === request.bindingDigest);
  check(Number.isSafeInteger(s.generation) && s.generation >= 0 && Number.isSafeInteger(s.loadedAt) && s.loadedAt > 0 && s.loadedAt <= Date.now() + 5000);
  check(Array.isArray(s.keySets) && s.keySets.length === request.keySets.length && Array.isArray(s.secrets) && s.secrets.length === request.secrets.length);
  const keySets = request.keySets.map(expected => {
    const matches = s.keySets.filter(k => k?.reference === expected.reference); check(matches.length === 1);
    const k = object(matches[0], ['reference', 'mappings', 'currentWrappingVersion', 'wrappingVersions', 'index', 'control']);
    const m = object(k.mappings, ['wrapping', 'index', 'control']);
    check(['wrapping', 'index', 'control'].every(role => m[role] === expected.mappings[role]) && k.currentWrappingVersion === expected.currentWrappingVersion);
    check(Array.isArray(k.wrappingVersions) && k.wrappingVersions.length === expected.wrappingVersions.length);
    const wrappingVersions = expected.wrappingVersions.map(pin => {
      const matches = k.wrappingVersions.filter(v => v?.keyVersion === pin.keyVersion); check(matches.length === 1);
      const w = object(matches[0], ['keyVersion', 'vaultVersion', 'value', 'attributes']);
      return { keyVersion: pin.keyVersion, ...value({ vaultVersion: w.vaultVersion, value: w.value, attributes: w.attributes }, pin.vaultVersion, true) };
    });
    const index = value(k.index, expected.indexVersion, true), control = value(k.control, expected.controlVersion, true);
    check(index.value !== control.value && wrappingVersions.every(v => v.value !== index.value && v.value !== control.value));
    return { reference: k.reference, mappings: { ...m }, currentWrappingVersion: k.currentWrappingVersion, wrappingVersions, index, control };
  });
  const secrets = request.secrets.map(expected => {
    const matches = s.secrets.filter(v => v?.mapping === expected.mapping); check(matches.length === 1);
    const v = object(matches[0], ['mapping', 'purpose', 'version', 'value', 'attributes']); check(v.purpose === expected.purpose && v.version === expected.version);
    const parsed = value({ vaultVersion: v.version, value: v.value, attributes: v.attributes }, expected.version);
    return { ...expected, value: parsed.value, attributes: parsed.attributes };
  });
  return freeze({ schemaVersion: 1, ...selectedScope, bindingRevision: s.bindingRevision, bindingDigest: s.bindingDigest, generation: s.generation, loadedAt: s.loadedAt, keySets, secrets });
}
function snapshotMappings(snapshot) {
  const result = Object.create(null);
  const add = (name, text) => { mapping(name); check(!own(result, name) && typeof text === 'string'); result[name] = text; };
  for (const keySet of snapshot.keySets) {
    const current = keySet.wrappingVersions.find(v => v.keyVersion === keySet.currentWrappingVersion); check(current);
    add(keySet.mappings.wrapping, current.value); add(keySet.mappings.index, keySet.index.value); add(keySet.mappings.control, keySet.control.value);
  }
  for (const secret of snapshot.secrets) add(secret.mapping, secret.value);
  return Object.freeze(result);
}
function selectSecretsStrategy(env = process.env) {
  const selected = env.SECRETS_KEYS_STRATEGY; if (selected === undefined) return 'ENV_VARIABLES';
  check(selected === 'ENV_VARIABLES' || selected === 'LOCAL_KEYVAULT'); return selected;
}
function json(text, max = 1048576) { check(typeof text === 'string' && Buffer.byteLength(text) <= max); return JSON.parse(text); }
function createRuntime(options) {
  check(typeof window === 'undefined');
  const env = { ...options.environment }, strategy = selectSecretsStrategy(env), fetcher = options.fetch ?? globalThis.fetch;
  const applicationToken = env.LOCAL_KEYVAULT_APPLICATION_TOKEN;
  if (applicationToken !== undefined) check(typeof applicationToken === 'string' && /^[\x21-\x7e]{32,4096}$/.test(applicationToken));
  let closed = false, startupDeadline, refreshPromise; const controllers = new Set(), cache = new Map(), pending = new Map();
  let base, bindings, auth, activeApplication;
  const discovery = env.LOCAL_KEYVAULT_BINDINGS_JSON === undefined, manifestPromises = new Map(), bindingPromises = new Map();
  const manifestEnvironment = env.LOCAL_KEYVAULT_ENVIRONMENT ?? 'development';
  if (strategy === 'LOCAL_KEYVAULT') {
    check(['development', 'test'].includes(env.NODE_ENV) && env.VERCEL === undefined && env.AWS_LAMBDA_FUNCTION_NAME === undefined && !['production', 'PROD'].includes(env.STAGE));
    const url = new URL(env.LOCAL_KEYVAULT_URL ?? 'http://127.0.0.1:4000');
    check(url.protocol === 'http:' && url.hostname === '127.0.0.1' && url.pathname === '/' && !url.search && !url.hash && !url.username && !url.password); base = url.origin;
    check(['development', 'dev', 'test'].includes(manifestEnvironment));
    bindings = discovery ? { schemaVersion: 1, applications: {}, tenants: [] } : object(json(env.LOCAL_KEYVAULT_BINDINGS_JSON), ['schemaVersion', 'applications', 'tenants']);
    check(bindings.schemaVersion === 1 && bindings.applications && typeof bindings.applications === 'object' && !Array.isArray(bindings.applications) && Object.keys(bindings.applications).length <= 16 && Array.isArray(bindings.tenants) && bindings.tenants.length <= 32);
    const entries = [...Object.entries(bindings.applications).map(([application, b]) => { check(/^[a-z][a-z0-9-]{0,63}$/.test(application)); return b; }), ...bindings.tenants];
    const seenTenants = new Set();
    for (const b of entries) { object(b, ['scope', 'request']); b.scope = scope(b.scope); check(['development', 'dev', 'test'].includes(b.scope.environment)); b.request = parseSnapshotRequest(b.request); for (const k of b.request.keySets) check(k.reference.split(':')[1] === b.scope.tenant); }
    for (const b of Object.values(bindings.applications)) check(b.scope.tenant === '_shared' && b.request.keySets.length === 0);
    for (const b of bindings.tenants) { check(b.scope.tenant !== '_shared' && !seenTenants.has(b.scope.tenant)); seenTenants.add(b.scope.tenant); }
    auth = options.credentialSupplier || applicationToken ? { schemaVersion: 1, grants: [] } : object(json(env.LOCAL_KEYVAULT_AUTH_JSON, 131072), ['schemaVersion', 'grants']); check(auth.schemaVersion === 1 && Array.isArray(auth.grants) && (auth.grants.length > 0 || applicationToken || typeof options.credentialSupplier === 'function') && auth.grants.length <= 64);
    const scopes = new Set();
    for (const grant of auth.grants) { object(grant, ['environment', 'tenant', 'token']); const g = scope({ environment: grant.environment, tenant: grant.tenant }), id = JSON.stringify(g); check(!scopes.has(id) && typeof grant.token === 'string' && /^[\x21-\x7e]{32,4096}$/.test(grant.token)); scopes.add(id); }
  }
  function active() { check(!closed); }
  async function requestJson(selectedScope, path, method, body, validate, maxBytes = 4 * 1024 * 1024, requestBudgetMs) {
    active(); startupDeadline ??= Date.now() + 30000; const remaining = Math.min(startupDeadline - Date.now(),requestBudgetMs??30000); check(remaining > 0);
    const controller = new AbortController(); controllers.add(controller); const timeout = setTimeout(() => controller.abort(), remaining);
    try {
      const grant = auth.grants.find(g => g.environment === selectedScope.environment && g.tenant === selectedScope.tenant);
      const token = applicationToken ?? (options.credentialSupplier ? await abortable(Promise.resolve().then(() => options.credentialSupplier(Object.freeze({ ...selectedScope }))), AbortSignal.any([controller.signal, AbortSignal.timeout(5000)])) : grant?.token);
      check(typeof token === 'string' && /^[\x21-\x7e]{32,4096}$/.test(token));
      for (let attempt = 0; attempt < 3; attempt++) {
        active(); let response;
        try {
          check(!applicationToken || activeApplication);
          response = await fetcher(base + (applicationToken ? '/local/runtime-access/' + activeApplication + path.slice(6) : path), { method, redirect: 'error', cache: 'no-store', signal: AbortSignal.any([controller.signal, AbortSignal.timeout(5000)]), headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', 'x-vault-environment': selectedScope.environment, 'x-vault-tenant': selectedScope.tenant }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
        } catch { if (attempt === 2 || controller.signal.aborted) throw unavailable(); await delay(250 * (attempt + 1), controller.signal); continue; }
        if (response.status === 503 && attempt < 2) { await response.body?.cancel(); await delay(250 * (attempt + 1), controller.signal); continue; }
        if (!response.ok || !response.headers.get('content-type')?.includes('application/json')) { await response.body?.cancel(); const error=unavailable();error.status=response.status;throw error; }
        const reader = response.body?.getReader(); check(reader); const chunks = []; let size = 0;
        try { for (;;) { const part = await reader.read(); if (part.done) break; size += part.value.byteLength; check(size <= maxBytes); chunks.push(Buffer.from(part.value)); } } finally { await reader.cancel().catch(() => undefined); }
        const result = validate(JSON.parse(Buffer.concat(chunks).toString('utf8'))); active(); return result;
      }
      throw unavailable();
    } catch(error) { const sanitized=unavailable();if([401,403,404,409,503].includes(error?.status))sanitized.status=error.status;throw sanitized; } finally { clearTimeout(timeout); controllers.delete(controller); }
  }
  async function load(scopeInput, requestInput) {
    active(); check(strategy === 'LOCAL_KEYVAULT');
    const selectedScope = scope(scopeInput), request = parseSnapshotRequest(requestInput);
    check(['development', 'dev', 'test'].includes(selectedScope.environment));
    for (const keySet of request.keySets) check(keySet.reference.split(':')[1] === selectedScope.tenant);
    const id = JSON.stringify([selectedScope, request.bindingDigest]);
    if (cache.has(id)) return cache.get(id);
    if (pending.has(id)) return pending.get(id);
    const operation = requestJson(selectedScope, '/local/runtime-snapshot', 'POST', request, raw => validateSnapshot(raw, selectedScope, request)).then(snapshot => { active(); cache.set(id, snapshot); return snapshot; });
    pending.set(id, operation); try { return await operation; } finally { pending.delete(id); }
  }
  function manifest(application, selectedScope, revision, requestBudgetMs) {
    active(); check(typeof application === 'string' && /^[a-z][a-z0-9-]{0,63}$/.test(application));
    const id = JSON.stringify([application, selectedScope, revision ?? 'current']);
    if (!manifestPromises.has(id)) manifestPromises.set(id, requestJson(selectedScope, '/local/runtime-manifests/' + application + (revision === undefined ? '' : '/' + revision), 'GET', undefined, raw => {
      const result = parseRuntimeManifest(raw);
      check(result.application === application && result.scope.environment === selectedScope.environment && result.scope.tenant === selectedScope.tenant && (revision === undefined || result.request.bindingRevision === revision));
      return freeze(result);
    }, 131072,requestBudgetMs).catch(error=>{if(revision!==undefined)manifestPromises.delete(id);throw error;}));
    return manifestPromises.get(id);
  }
  async function processBinding(application) {
    if(applicationToken){check(activeApplication===undefined||activeApplication===application);activeApplication=application;}
    if (!discovery) { check(own(bindings.applications, application)); return bindings.applications[application]; }
    if (activeApplication === undefined) activeApplication = application;
    check(activeApplication === application);
    if (!own(bindings.applications, application)) {
      const m = await manifest(application, { environment: manifestEnvironment, tenant: '_shared' });
      active(); bindings.applications[application] = { scope: m.scope, request: m.request };
    }
    return bindings.applications[application];
  }
  async function tenantBinding(tenant, revision) {
    part(tenant); check(tenant !== '_shared' && Number.isSafeInteger(revision) && revision > 0);
    if (!discovery) { const b = bindings.tenants.find(b => b.scope.tenant === tenant); check(b && b.request.bindingRevision === revision); return b; }
    check(activeApplication !== undefined);
    const parent = await manifest(activeApplication, { environment: manifestEnvironment, tenant: '_shared' });
    const ref = parent.tenants.find(t => t.tenant === tenant); check(ref && ref.bindingRevision === revision);
    const m = await manifest(activeApplication, { environment: manifestEnvironment, tenant }, revision);
    check(m.request.bindingDigest === ref.bindingDigest);
    let b = bindings.tenants.find(b => b.scope.tenant === tenant);
    if (!b) { b = { scope: m.scope, request: m.request }; bindings.tenants.push(b); }
    else { b.scope=m.scope;b.request=m.request; }
    return b;
  }
  async function loadApplication(application) {
    active(); check(strategy === 'LOCAL_KEYVAULT'); return freeze(structuredClone(await processBinding(application)));
  }
  async function loadTenantBinding(application,tenant){
    active();check(strategy==='LOCAL_KEYVAULT');await processBinding(application);part(tenant);check(tenant!=='_shared');
    let selected;
    if(discovery){const parent=await manifest(application,{environment:manifestEnvironment,tenant:'_shared'});const ref=parent.tenants.find(r=>r.tenant===tenant);check(ref);selected=await tenantBinding(tenant,ref.bindingRevision);}
    else{selected=bindings.tenants.find(b=>b.scope.tenant===tenant);check(selected);}
    return freeze(structuredClone(selected));
  }
  async function loadBindings(application) {
    active(); check(strategy === 'LOCAL_KEYVAULT'); await processBinding(application);
    if (discovery) {
      if (!bindingPromises.has(application)) bindingPromises.set(application, (async () => {
        const parent = await manifest(application, { environment: manifestEnvironment, tenant: '_shared' });
        await Promise.all(parent.tenants.map(ref => tenantBinding(ref.tenant, ref.bindingRevision))); active();
        return freeze(structuredClone(bindings));
      })());
      return bindingPromises.get(application);
    }
    return freeze(structuredClone(bindings));
  }
  async function refreshBindings(application) {
    active();check(strategy==='LOCAL_KEYVAULT');
    if(!discovery)return loadBindings(application);
    if(refreshPromise)return refreshPromise;
    refreshPromise=(async()=>{
      startupDeadline=Date.now()+30000;manifestPromises.clear();bindingPromises.delete(application);
      await processBinding(application);
      const parent=await manifest(application,{environment:manifestEnvironment,tenant:'_shared'});
      const results=await Promise.allSettled(parent.tenants.map(async ref=>{
        const selectedScope={environment:manifestEnvironment,tenant:ref.tenant};
        const child=await manifest(application,selectedScope,ref.bindingRevision,2000);
        check(child.request.bindingDigest===ref.bindingDigest);
        return {scope:child.scope,request:child.request};
      }));
      active();const assigned=new Set(parent.tenants.map(t=>t.tenant));for(const key of cache.keys()){const selected=JSON.parse(key)[0];if(selected.tenant!=='_shared'&&!assigned.has(selected.tenant))cache.delete(key);}
      bindings.applications[application]={scope:parent.scope,request:parent.request};
      bindings.tenants=results.flatMap((result,index)=>{
        if(result.status==='fulfilled')return[result.value];
        const tenant=parent.tenants[index].tenant;
        if([401,403].includes(result.reason?.status)){for(const key of cache.keys())if(JSON.parse(key)[0].tenant===tenant)cache.delete(key);return[];}
        const previous=bindings.tenants.find(t=>t.scope.tenant===tenant);return previous?[previous]:[];
      });
      const result=freeze(structuredClone(bindings));bindingPromises.set(application,Promise.resolve(result));return result;
    })().finally(()=>{refreshPromise=undefined;});return refreshPromise;
  }
  async function loadProcess(application, policy) {
    active(); check(Array.isArray(policy.allowedMappings) && policy.allowedMappings.length <= 256 && new Set(policy.allowedMappings).size === policy.allowedMappings.length); policy.allowedMappings.forEach(mapping);
    const required = policy.requiredMappings ?? []; check(Array.isArray(required) && required.every(name => policy.allowedMappings.includes(name)));
    if (strategy === 'ENV_VARIABLES') return { strategy, mappings: Object.freeze(Object.fromEntries(policy.allowedMappings.filter(k => env[k] !== undefined).map(k => [k, env[k]]))) };
    const b = await processBinding(application);
    const requestedNames = b.request.secrets.map(s => s.mapping); check(requestedNames.every(k => policy.allowedMappings.includes(k)) && required.every(k => requestedNames.includes(k)));
    const snapshot = await load(b.scope, b.request), mappings = snapshotMappings(snapshot); check(required.every(k => typeof mappings[k] === 'string' && mappings[k].length > 0));
    return Object.freeze({ strategy, mappings, snapshot });
  }
  async function loadTenant(tenant, revision) {
    active(); check(strategy === 'LOCAL_KEYVAULT'); const b = await tenantBinding(tenant, revision); return load(b.scope, b.request);
  }
  function close() { closed = true; for (const c of controllers) c.abort(); controllers.clear(); cache.clear(); pending.clear(); manifestPromises.clear(); bindingPromises.clear(); if (auth) auth.grants.length = 0; }
  return Object.freeze({ load, loadApplication, loadTenantBinding, loadBindings, refreshBindings, loadProcess, loadTenant, close });
}
function abortable(promise, signal) { return new Promise((resolve, reject) => { function abort() { reject(unavailable()); } signal.addEventListener('abort', abort, { once: true }); if (signal.aborted) abort(); Promise.resolve(promise).then(resolve, () => reject(unavailable())).finally(() => signal.removeEventListener('abort', abort)); }); }
function delay(ms, signal) { return new Promise((resolve, reject) => { const timer = setTimeout(done, ms); function done() { signal.removeEventListener('abort', abort); resolve(); } function abort() { clearTimeout(timer); signal.removeEventListener('abort', abort); reject(unavailable()); } signal.addEventListener('abort', abort, { once: true }); if (signal.aborted) abort(); }); }
function createSecretsRuntime(options) { try { return createRuntime(options); } catch { throw unavailable(); } }
exports.selectSecretsStrategy = selectSecretsStrategy;
exports.bindingDigest = bindingDigest;
exports.parseSnapshotRequest = parseSnapshotRequest;
exports.snapshotMappings = snapshotMappings;
exports.createSecretsRuntime = createSecretsRuntime;

exports.parseRuntimeManifest = parseRuntimeManifest;
exports.createApplicationRuntime = require('./application-client.cjs').createApplicationRuntime;
exports.parseApplicationDescriptor = require('./application-client.cjs').parseApplicationDescriptor;

exports.applicationSnapshotFromLegacy = require('./application-client.cjs').applicationSnapshotFromLegacy;

exports.applicationDescriptorFromLegacy = require('./application-client.cjs').applicationDescriptorFromLegacy;
exports.applicationDescriptorFromTenantLegacy=require('./application-client.cjs').applicationDescriptorFromTenantLegacy;
exports.applicationSnapshotFromTenantLegacy=require('./application-client.cjs').applicationSnapshotFromTenantLegacy;

exports.createTenantRotationCoordinator=require('./tenant-rotation.cjs').createTenantRotationCoordinator;
exports.createMongoTenantRotationStore=require('./tenant-rotation.cjs').createMongoTenantRotationStore;

exports.createMemoryRuntime=require('./memory-runtime.cjs').createMemoryRuntime;
