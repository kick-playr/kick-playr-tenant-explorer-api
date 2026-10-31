import test from 'node:test';
import assert from 'node:assert/strict';
import { MongoInvitationRepository } from '../src/invitations/repository.js';
test('native invitation store fences tenant configuration without rewriting runtime authority', async () => {
  const writes: { collection: string; filter: unknown }[] = [];
  let ended = false,
    options: any;
  const session = {
    withTransaction: async (fn: () => Promise<unknown>, o: any) => {
      options = o;
      return fn();
    },
    endSession: async () => {
      ended = true;
    },
  };
  const db = {
    collection(name: string) {
      return {
        findOne: async (filter: any) =>
          name === 'tenantDefinitions'
            ? {
                id: 'club',
                environment: 'development',
                status: 'provisioning',
                configRevision: 1,
                public: { name: 'Club' },
              }
            : name === 'tenantRuntimeAuthorities'
              ? {
                  configRevision: 1,
                  identityRealm: 'https://club.example',
                  authorityRevision: 3,
                  users: [],
                }
              : null,
        updateOne: async (filter: unknown) => {
          writes.push({ collection: name, filter });
          return { matchedCount: 1 };
        },
        replaceOne: async (filter: unknown) => {
          writes.push({ collection: name, filter });
        },
        insertOne: async (filter: unknown) => {
          writes.push({ collection: name, filter });
        },
      };
    },
  };
  const repo = new MongoInvitationRepository(
    { startSession: () => session, db: () => db } as any,
    'control',
  );
  await repo.transact(
    { environment: 'development', tenantId: 'club' },
    async (tx) => {
      tx.state.owner = {
        issuer: 'https://club.example',
        subject: 'user_owner',
      };
    },
  );
  assert.equal(ended, true);
  assert.equal(options.readConcern.level, 'snapshot');
  assert.equal(options.writeConcern.w, 'majority');
  assert.equal(
    writes.some((w) => w.collection === 'tenantRuntimeAuthorities'),
    false,
  );
  assert.deepEqual(writes[0]!.filter, {
    environment: 'development',
    id: 'club',
    configRevision: 1,
  });
  assert.equal(writes[1]!.collection, 'tenantManagerInvitations');
  await repo.transact(
    { environment: 'development', tenantId: 'club' },
    async (tx) => {
      await tx.revokeRuntime!('https://club.example', 'user_owner');
    },
  );
  assert.deepEqual(
    writes.find((w) => w.collection === 'tenantRuntimeAuthorities')?.filter,
    { environment: 'development', tenantId: 'club', authorityRevision: 3 },
  );
  await assert.rejects(
    repo.transact(
      { environment: 'development', tenantId: '../other' },
      async () => {},
    ),
  );
});
