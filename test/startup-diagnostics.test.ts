import test from 'node:test';
import assert from 'node:assert/strict';
import { StartupDiagnostics } from '../src/startup-diagnostics.js';

test('diagnostics redact malformed configuration and unrecognized error codes', async () => {
  const events: any[] = [];
  const diagnostics = new StartupDiagnostics(event => events.push(event));
  diagnostics.configuration({ SECRETS_KEYS_STRATEGY: 'strategy-canary', NODE_ENV: 'node-env-canary' });
  diagnostics.configuration({ SECRETS_KEYS_STRATEGY: 'LOCAL_KEYVAULT', NODE_ENV: 'development', LOCAL_KEYVAULT_AUTH_JSON: 'token-canary', LOCAL_KEYVAULT_BINDINGS_JSON: '{"schemaVersion":1,"applications":{}}' });
  await assert.rejects(diagnostics.run('database.connect', async () => {
    throw Object.assign(Error('mongodb://password-canary@host/db'), { code: 'secret-code-canary' });
  }));
  for (const canary of ['strategy-canary', 'node-env-canary', 'token-canary', 'password-canary', 'secret-code-canary']) assert.ok(!JSON.stringify(events).includes(canary));
  assert.equal(events[0].strategy, 'invalid');
  assert.ok(events[1].invalid.includes('LOCAL_KEYVAULT_AUTH_JSON'));
  assert.ok(events[1].invalid.includes('LOCAL_KEYVAULT_BINDINGS_JSON.applications.explorer-api'));
});

test('vault transport status and network diagnostics preserve responses and exceptions', async () => {
  const events: any[] = [];
  const diagnostics = new StartupDiagnostics(event => events.push(event));
  const response = new Response('body-canary', { status: 403, headers: { 'private-header': 'header-canary' } });
  assert.equal(await diagnostics.vaultRequest(async () => response), response);
  assert.equal(await response.text(), 'body-canary');
  const error = Object.assign(Error('fetch-url-canary'), { cause: Object.assign(Error('cause-canary'), { code: 'ECONNREFUSED' }) });
  await assert.rejects(diagnostics.vaultRequest(async () => { throw error; }), caught => caught === error);
  assert.ok(events.some(event => event.phase === 'failure' && event.status === 403));
  assert.ok(events.some(event => event.code === 'ECONNREFUSED'));
  for (const canary of ['body-canary', 'header-canary', 'fetch-url-canary', 'cause-canary']) assert.ok(!JSON.stringify(events).includes(canary));
});


test('manifest startup needs authentication but no local binding document', () => {
  const events: any[] = [];
  const diagnostics = new StartupDiagnostics(event => events.push(event));
  diagnostics.configuration({ SECRETS_KEYS_STRATEGY: 'LOCAL_KEYVAULT', NODE_ENV: 'development' });
  assert.deepEqual(events[0].missing, ['LOCAL_KEYVAULT_AUTH_JSON']);
  assert.equal(events[0].bindingSource, 'vault-manifest');
  diagnostics.configuration({ SECRETS_KEYS_STRATEGY: 'LOCAL_KEYVAULT', NODE_ENV: 'development', LOCAL_KEYVAULT_AUTH_JSON: '{"schemaVersion":1,"grants":[{}]}', LOCAL_KEYVAULT_BINDINGS_JSON: 'private-binding-canary' });
  assert.equal(events[1].bindingSource, 'environment');
  assert.deepEqual(events[1].invalid, ['LOCAL_KEYVAULT_BINDINGS_JSON']);
  assert.ok(!JSON.stringify(events).includes('private-binding-canary'));
});


test('manifest and snapshot 404 diagnostics identify only the finite operation', async () => {
  const events: any[] = [];
  const diagnostics = new StartupDiagnostics(event => events.push(event));
  const manifest = new Response('manifest-private-canary', { status: 404 });
  assert.equal(await diagnostics.vaultRequest(async () => manifest, 'manifest'), manifest);
  assert.equal(await manifest.text(), 'manifest-private-canary');
  await diagnostics.vaultRequest(async () => new Response('snapshot-private-canary', { status: 404 }));
  assert.ok(events.some(event => event.operation === 'manifest' && event.status === 404 && event.hint.includes('Publish the application runtime manifest')));
  assert.ok(events.some(event => event.operation === 'snapshot' && event.status === 404 && event.hint.includes('pinned snapshot versions')));
  assert.ok(!JSON.stringify(events).includes('private-canary'));
});
