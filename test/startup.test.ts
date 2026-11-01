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
