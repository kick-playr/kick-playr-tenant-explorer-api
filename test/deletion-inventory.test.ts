import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  deriveInventory,
  DeletionInventoryResolver,
  snapshotCollection,
} from '../src/deletion/inventory.js';
import { CredentialVault } from '../src/vault.js';
import { encodeRuntimeEnvelope } from '../src/runtime-configuration.js';
import type { MongoClient } from 'mongodb';
const scope = { environment: 'development', tenantId: 'club' };
const uri = (db: string) =>
  `mongodb://user:PRIVATE_SECRET@cluster.invalid/${db}?tls=true&authSource=admin`;
const root = (tenants: unknown[] = [], pending: unknown[] = []) => ({
  version: 2,
  profile: 'workflow-real',
  tenants,
  pendingMongoBindings: pending,
});
test('registered tenant and pending bindings derive names without an environment manifest, deduplicating the selected database', () => {
  const m = deriveInventory(
    root(
      [
        { id: 'club', mongoUri: uri('clubdata') },
        { id: 'other', mongoUri: uri('otherdata') },
      ],
      [{ tenantId: 'club', mongoUri: uri('clubdata') }],
    ),
    scope,
    'control',
  );
  assert.equal(m.targets.length, 1);
  assert.equal(m.targets[0]!.database, 'clubdata');
  assert.equal(m.controlOnly, false);
});
test('invalid, ambiguous, shared and protected inventory never becomes empty safe inventory', () => {
  for (const payload of [
    { version: 2, tenants: null },
    root([null]),
    root([{ id: 'club', mongoUri: 'not-uri' }]),
    root([{ id: 'club', mongoUri: uri('admin') }]),
    root([{ id: 'club', mongoUri: uri('control') }]),
    root([
      { id: 'club', mongoUri: uri('clubdata') },
      { id: 'other', mongoUri: uri('clubdata') },
    ]),
    root([
      { id: 'club', mongoUri: uri('clubdata') },
      { id: 'club', mongoUri: uri('second') },
    ]),
  ])
    assert.throws(() => deriveInventory(payload, scope, 'control'));
  assert.throws(
    () =>
      deriveInventory(
        root(),
        { ...scope, environment: 'production' },
        'control',
      ),
    /unsupported/i,
  );
});
test('a valid authoritative development envelope with no selected binding explicitly describes control-only cleanup', () => {
  const m = deriveInventory(
    root([{ id: 'other', mongoUri: uri('otherdata') }]),
    scope,
    'control',
  );
  assert.equal(m.controlOnly, true);
  assert.equal(m.targets.length, 0);
  assert.throws(() => deriveInventory({}, scope, 'control'));
});
function fixture() {
  const key = Buffer.alloc(32, 1),
    vault = new CredentialVault(Buffer.alloc(32, 2));
  let payload = root([{ id: 'club', mongoUri: uri('clubdata') }]);
  const snapshots = new Map<string, any>();
  let operation: any = null;
  const client = {
    db: () => ({
      collection: (name: string) => ({
        findOne: async (filter: any) =>
          name === 'tenantWorkflowConfiguration'
            ? encodeRuntimeEnvelope(payload, key, 'control')
            : name === 'tenantDeletionOperations'
              ? operation
              : (snapshots.get(filter._id) ?? null),
        insertOne: async (row: any) => {
          snapshots.set(row._id, structuredClone(row));
        },
        deleteOne: async (filter: any) => {
          snapshots.delete(filter._id);
        },
      }),
    }),
  } as unknown as MongoClient;
  return {
    resolver: new DeletionInventoryResolver(client, 'control', key, vault),
    snapshots,
    get payload() {
      return payload;
    },
    set payload(v) {
      payload = v;
    },
    set operation(v: any) {
      operation = v;
    },
  };
}
test('claim recomputes preview and freezes encrypted operation-bound credentials; retries survive runtime prune', async () => {
  const f = fixture();
  const preview = await f.resolver.resolve(scope);
  const op = {
    id: 'operation',
    manifestRevision: preview.digest,
    phase: 'purging',
  };
  await f.resolver.freeze(scope, op.id, preview.digest, {} as never);
  f.operation = op;
  const stored = [...f.snapshots.values()][0];
  assert.ok(!JSON.stringify(stored).includes('PRIVATE_SECRET'));
  assert.ok(!JSON.stringify(stored).includes('mongodb'));
  f.payload = root();
  const retried = await f.resolver.resolve(scope);
  assert.equal(retried.targets[0]!.uri, uri('clubdata'));
  assert.equal(retried.digest, preview.digest);
  f.operation = { ...op, id: 'different-operation' };
  await assert.rejects(f.resolver.resolve(scope), /snapshot/i);
});
test('ciphertext cannot be substituted across scope or inventory revision; unknown current inventory blocks retry', async () => {
  const f = fixture();
  const preview = await f.resolver.resolve(scope);
  await f.resolver.freeze(scope, 'operation', preview.digest, {} as never);
  f.operation = {
    id: 'operation',
    phase: 'failed',
    manifestRevision: preview.digest,
  };
  const snapshot = [...f.snapshots.values()][0];
  snapshot.inventoryRevision = 'different';
  await assert.rejects(f.resolver.resolve(scope), /snapshot/i);
  snapshot.inventoryRevision = preview.digest;
  f.payload = {} as any;
  await assert.rejects(f.resolver.resolve(scope), /inventory/i);
});
test('stale preview cannot freeze different targets', async () => {
  const f = fixture();
  const preview = await f.resolver.resolve(scope);
  f.payload = root([{ id: 'club', mongoUri: uri('changed') }]);
  await assert.rejects(
    f.resolver.freeze(scope, 'op', preview.digest, {} as never),
    /changed/i,
  );
  assert.equal(f.snapshots.size, 0);
});

test('snapshot ciphertext substitution across tenant or inventory revision is rejected even when public headers are rewritten', async () => {
  const f = fixture(),
    initial = await f.resolver.resolve(scope);
  await f.resolver.freeze(scope, 'operation', initial.digest, {} as never);
  const original = [...f.snapshots.values()][0];
  const substituted = structuredClone(original);
  substituted.tenantId = 'other';
  substituted._id = 'development/other/operation';
  f.snapshots.set(substituted._id, substituted);
  f.operation = {
    id: 'operation',
    phase: 'failed',
    manifestRevision: initial.digest,
  };
  await assert.rejects(
    f.resolver.resolve({ ...scope, tenantId: 'other' }),
    /snapshot/i,
  );
  const different = 'b'.repeat(64);
  original.inventoryRevision = different;
  f.operation = {
    id: 'operation',
    phase: 'failed',
    manifestRevision: different,
  };
  await assert.rejects(f.resolver.resolve(scope), /snapshot/i);
});
test('already latched legacy operation without snapshot cannot silently derive replacement targets', async () => {
  const f = fixture();
  const preview = await f.resolver.resolve(scope);
  f.operation = {
    id: 'legacy',
    phase: 'failed',
    manifestRevision: preview.digest,
  };
  await assert.rejects(f.resolver.resolve(scope), /snapshot/i);
  assert.equal(f.snapshots.size, 0);
});
