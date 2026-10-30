import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MongoClient, type Document } from 'mongodb';
import { MongoRepository } from '../src/repository.js';
import type { Aggregate } from '../src/contracts.js';

const aggregate: Aggregate = {
  definition: {
    id: 'winikon',
    environment: 'development',
    hostname: 'winikon.localhost:4311',
    aliases: ['alias.localhost:4311'],
    status: 'active',
    configRevision: 5,
    public: { name: 'FC Winikon', locale: 'de-CH' },
    secretReferences: { mongoUri: 'local:mongo', key: 'local:key' },
  },
  authority: {
    schema: 1,
    tenantId: 'winikon',
    environment: 'development',
    configRevision: 5,
    authorityRevision: 9,
    status: 'active',
    identityRealm: 'https://example.clerk.accounts.dev',
    hostnames: ['winikon.localhost:4311', 'alias.localhost:4311'],
    users: [],
    services: [],
  },
  metadata: { configuration: {}, credentials: [], integrations: [] },
};
function nativeFixture(authorityRevision = 8) {
  let transactionOptions: unknown;
  let ended = false;
  let committed = false;
  let persisted: Document[] = [];
  const session = {
    withTransaction: async (work: () => Promise<unknown>, options: unknown) => {
      transactionOptions = options;
      const result = await work();
      committed = true;
      return result;
    },
    endSession: async () => {
      ended = true;
    },
  };
  const client = {
    startSession: () => session,
    db: () => ({
      collection: (name: string) => ({
        updateOne: async (
          filter: Document,
          update: Document,
          options: Document,
        ) => {
          assert.equal(options.session, session);
          if (name === 'tenantRuntimeAuthorities') {
            if (filter.authorityRevision !== authorityRevision)
              return { matchedCount: 0 };
            persisted.push(update.$set);
          }
          return { matchedCount: 1 };
        },
        deleteMany: async () => ({}),
        insertMany: async (rows: Document[]) => {
          persisted = [...persisted, ...rows];
        },
        insertOne: async () => ({}),
      }),
    }),
  } as unknown as MongoClient;
  const repository = new MongoRepository(client, 'control');
  return {
    repository,
    get committed() {
      return committed;
    },
    get ended() {
      return ended;
    },
    get transactionOptions() {
      return transactionOptions;
    },
    get persisted() {
      return persisted;
    },
  };
}

test('native adapter rejects an intervening runtime authority change before committing', async () => {
  const f = nativeFixture(10);
  await assert.rejects(
    f.repository.transaction((tx) => tx.save(structuredClone(aggregate), 4)),
    /authority|changed|reload/i,
  );
  assert.equal(f.committed, false);
  assert.equal(f.ended, true);
});

test('native adapter writes matching host revisions and commits with snapshot/majority', async () => {
  const f = nativeFixture();
  await f.repository.transaction((tx) =>
    tx.save(structuredClone(aggregate), 4),
  );
  assert.equal(f.committed, true);
  assert.equal(f.ended, true);
  assert.deepEqual((f.transactionOptions as Document).readConcern, {
    level: 'snapshot',
  });
  assert.equal((f.transactionOptions as Document).writeConcern.w, 'majority');
  assert.equal(
    f.persisted.filter((row) => row.hostname && row.configRevision === 5)
      .length,
    2,
  );
});
