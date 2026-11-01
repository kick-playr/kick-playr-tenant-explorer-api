import test from 'node:test';
import assert from 'node:assert/strict';
import { startExplorer } from '../src/startup.js';

test('dependent server code is imported only after complete process secret loading', async () => {
  const events: string[] = [];
  const secrets = {
    environment: { CLERK_SECRET_KEY: 'vault' },
    close: () => events.push('close'),
  };
  await startExplorer(
    {},
    async () => {
      events.push('secrets');
      return secrets as any;
    },
    async () => {
      events.push('import');
      return {
        bootstrap: async (loaded: unknown) => {
          assert.equal(loaded, secrets);
          events.push('bootstrap');
        },
      };
    },
  );
  assert.deepEqual(events, ['secrets', 'import', 'bootstrap']);
});
test('failed secret startup never imports dependent server code; failed construction closes loaded source', async () => {
  let imported = false,
    closed = false;
  await assert.rejects(
    startExplorer(
      {},
      async () => {
        throw Error('missing');
      },
      async () => {
        imported = true;
        return {} as any;
      },
    ),
  );
  assert.equal(imported, false);
  await assert.rejects(
    startExplorer(
      {},
      async () =>
        ({
          environment: {},
          close: () => {
            closed = true;
          },
        }) as any,
      async () => ({
        bootstrap: async () => {
          throw Error('fail');
        },
      }),
    ),
  );
  assert.equal(closed, true);
});

test('startup reports missing vault settings and the failing stage without exposing error payloads', async () => {
  const events: any[] = [];
  await assert.rejects((startExplorer as any)(
    { SECRETS_KEYS_STRATEGY: 'LOCAL_KEYVAULT', LOCAL_KEYVAULT_AUTH_JSON: '{"schemaVersion":1,"grants":[{"token":"auth-token-canary"}]}' },
    async () => { throw Error('mongodb://user:password-canary@private-host/secret-database'); },
    async () => { throw Error('must not import'); },
    (event: unknown) => events.push(event),
  ));
  const config = events.find(event => event.event === 'explorer.startup.configuration');
  assert.ok(config);
  assert.ok(config.missing.includes('NODE_ENV'));
  assert.ok(!config.missing.includes('LOCAL_KEYVAULT_BINDINGS_JSON'));
  assert.equal(config.bindingSource, 'vault-manifest');
  assert.ok(events.some(event => event.stage === 'secrets.process' && event.phase === 'failure'));
  const output = JSON.stringify(events);
  for (const secret of ['auth-token-canary', 'password-canary', 'private-host', 'secret-database']) assert.ok(!output.includes(secret));
});

test('startup diagnostics identify import failures and observer errors never replace startup results', async () => {
  const events: any[] = [];
  let closed = false;
  const source = { close: () => { closed = true; } };
  await assert.rejects((startExplorer as any)(
    {}, async () => source,
    async () => { throw Object.assign(Error('private-module-canary'), { code: 'ERR_MODULE_NOT_FOUND' }); },
    (event: unknown) => events.push(event),
  ));
  assert.equal(closed, true);
  assert.ok(events.some(event => event.stage === 'server.import' && event.phase === 'failure' && event.code === 'ERR_MODULE_NOT_FOUND'));
  assert.ok(!JSON.stringify(events).includes('private-module-canary'));
  await (startExplorer as any)({}, async () => source, async () => ({ bootstrap: async () => {} }), () => { throw Error('observer failed'); });
});
