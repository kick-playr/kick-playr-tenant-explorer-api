import {
  deriveInventory,
  DeletionInventoryResolver,
  snapshotCollection,
} from '../src/deletion/inventory.js';
import { CredentialVault } from '../src/vault.js';
import { decodeRuntimeEnvelope } from '../src/runtime-configuration.js';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MongoClient } from 'mongodb';
import { MongoPurgePort, pruneRuntime } from '../src/deletion/mongo.js';
import { encodeRuntimeEnvelope } from '../src/runtime-configuration.js';
const scope = { environment: 'development', tenantId: 'club' };
const target = {
  id: 'db',
  connectionVariable: 'CLUB_DB_URI',
  database: 'clubdata',
  exclusive: true,
  evidence: 'operator verified inventory',
};
const entry = {
  ...scope,
  complete: true,
  revision: 'one',
  targets: [target],
  scopedCollections: [],
};
function port(tenants: unknown[], pending: unknown[] = []) {
  const key = Buffer.alloc(32, 1);
  const row = encodeRuntimeEnvelope(
    {
      version: 2,
      profile: 'workflow-real',
      tenants,
      pendingMongoBindings: pending,
    },
    key,
    'control',
  );
  const client = {
    db: () => ({
      collection: (name: string) => ({
        findOne: async () =>
          name === 'tenantWorkflowConfiguration' ? row : null,
      }),
    }),
  } as unknown as MongoClient;
  return new MongoPurgePort(
    client,
    'control',
    key,
    new DeletionInventoryResolver(
      client,
      'control',
      key,
      new CredentialVault(Buffer.alloc(32, 2)),
    ),
  );
}
test('inventory derives bound databases and rejects a cross-tenant shared binding without a manifest', async () => {
  await assert.rejects(
    port([
      { id: 'club', mongoUri: 'mongodb://localhost/clubdata' },
      { id: 'other', mongoUri: 'mongodb://localhost/clubdata' },
    ]).inventory(scope),
    /shared/i,
  );
  const result = await port([
    { id: 'club', mongoUri: 'mongodb://localhost/discovered' },
  ]).inventory(scope);
  assert.equal(result.complete, true);
  assert.equal(result.targets[0]!.label, 'Database discovered');
  assert.ok(!JSON.stringify(result).includes('mongodb:'));
});
test('valid empty registered inventory explicitly describes control-only cleanup', async () => {
  const result = await port([]).inventory(scope);
  assert.equal(result.complete, true);
  assert.equal(result.controlOnly, true);
});
test('encrypted runtime cleanup removes exact tenant only and preserves shared realms and different environments', () => {
  const root = {
    tenants: [{ id: 'club' }, { id: 'other' }],
    pendingMongoBindings: [{ tenantId: 'club' }],
    explorer: {
      clubRuntimes: [scope, { environment: 'production', tenantId: 'club' }],
      setupRuntimes: [scope],
      keyBindings: {
        version: 1,
        bindings: [scope, { ...scope, tenantId: 'other' }],
      },
      clubRealms: [{ issuer: 'shared' }],
      frontendHosts: { 'club.ch': { publishableKey: 'public' } },
    },
  };
  const result = pruneRuntime(root, scope);
  assert.deepEqual(result.tenants, [{ id: 'other' }]);
  assert.deepEqual(result.explorer.clubRuntimes, [
    { environment: 'production', tenantId: 'club' },
  ]);
  assert.deepEqual(result.explorer.clubRealms, root.explorer.clubRealms);
  assert.deepEqual(root.tenants, [{ id: 'club' }, { id: 'other' }]);
});

import { MongoDeletionStore } from '../src/deletion/mongo.js';
import { DeletionService } from '../src/deletion/service.js';
import { checklist } from '../src/deletion/contracts.js';
import type { Document } from 'mongodb';
function native() {
  const key = Buffer.alloc(32, 3);
  const rows: Record<string, Document[]> = {
    tenantDefinitions: [
      {
        id: 'club',
        environment: 'development',
        hostname: 'club.ch',
        aliases: [],
        status: 'active',
        configRevision: 1,
        invitationFence: 12,
        writeFence: 8,
        public: { name: 'Club', locale: 'de-CH' },
        secretReferences: { mongoUri: 'ref', key: 'ref' },
      },
    ],
    tenantRuntimeAuthorities: [
      {
        schema: 1,
        environment: 'development',
        tenantId: 'club',
        status: 'active',
        configRevision: 1,
        authorityRevision: 1,
        supportRevision: 1,
        users: [],
        services: [],
        identityRealm: 'https://realm.example',
        hostnames: ['club.ch'],
      },
    ],
    tenantExplorerConfiguration: [
      {
        environment: 'development',
        tenantId: 'club',
        credentials: [],
        integrations: [],
        configuration: { name: 'personal' },
      },
    ],
    tenantHostBindings: [
      {
        environment: 'development',
        tenantId: 'club',
        hostname: 'club.ch',
        configRevision: 1,
      },
    ],
    tenantManagerInvitations: [
      { _id: 'development/club', revision: 1, principals: [], invitations: [] },
    ],
    tenantManagerSetupProofs: [
      { environment: 'development', tenantId: 'club', personal: 'remove' },
      { environment: 'production', tenantId: 'club', personal: 'keep' },
    ],
    tenantWorkflowConfiguration: [
      encodeRuntimeEnvelope(
        {
          version: 2,
          profile: 'workflow-real',
          tenants: [
            { id: 'club', mongoUri: 'mongodb://localhost/clubdata' },
            { id: 'other', mongoUri: 'mongodb://localhost/otherdata' },
          ],
          pendingMongoBindings: [],
          explorer: {
            clubRuntimes: [scope],
            keyBindings: { bindings: [scope] },
          },
        },
        key,
        'control',
      ),
    ],
  };
  let failDiscard = false;
  const calls: { name: string; filter: Document }[] = [];
  const match = (r: Document, f: Document) =>
    Object.entries(f).every(([k, v]) => r[k] === v);
  const session = {
    withTransaction: async (work: () => Promise<any>, options: Document) => {
      assert.equal(options.readPreference, 'primary');
      assert.equal(options.writeConcern.w, 'majority');
      const before = structuredClone(rows);
      try {
        return await work();
      } catch (error) {
        for (const key of Object.keys(rows)) delete rows[key];
        Object.assign(rows, before);
        throw error;
      }
    },
    endSession: async () => {},
  };
  const collection = (name: string) => ({
    findOne: async (f: Document, o: Document) => {
      const row = rows[name]?.find((r) => match(r, f));
      if (!row) return null;
      const copy = structuredClone(row);
      if (o?.projection?._id === 0) delete copy._id;
      return copy;
    },
    updateOne: async (f: Document, u: Document, opts: Document = {}) => {
      calls.push({ name, filter: f });
      assert.ok(
        !Object.hasOwn(u.$set ?? {}, 'invitationFence'),
        'do not $set and $inc same path',
      );
      let row = rows[name]?.find((r) => match(r, f));
      if (!row && opts.upsert) {
        row = structuredClone(f);
        (rows[name] ??= []).push(row);
      }
      if (!row) return { matchedCount: 0 };
      Object.assign(row, u.$set);
      for (const [k, v] of Object.entries(u.$inc ?? {}))
        row[k] = (row[k] ?? 0) + Number(v);
      for (const k of Object.keys(u.$unset ?? {})) delete row[k];
      return { matchedCount: 1 };
    },
    updateMany: async (f: Document, u: Document) => {
      for (const r of rows[name] ?? [])
        if (match(r, f)) Object.assign(r, u.$set);
      return {};
    },
    replaceOne: async (f: Document, r: Document, o: Document) => {
      const entries = (rows[name] ??= []);
      const i = entries.findIndex((x) => match(x, f));
      if (i >= 0) entries[i] = structuredClone(r);
      else if (o?.upsert) entries.push(structuredClone(r));
      return { matchedCount: i >= 0 ? 1 : 0 };
    },
    insertOne: async (r: Document) => {
      (rows[name] ??= []).push(structuredClone(r));
    },
    deleteMany: async (f: Document) => {
      calls.push({ name, filter: f });
      rows[name] = (rows[name] ?? []).filter((r) => !match(r, f));
      return {};
    },
    deleteOne: async (f: Document) => {
      if (name === snapshotCollection && failDiscard) {
        failDiscard = false;
        throw new Error('Fixture finalization interruption');
      }
      rows[name] = (rows[name] ?? []).filter((r) => !match(r, f));
      return {};
    },
    countDocuments: async (f: Document) =>
      (rows[name] ?? []).filter((r) => match(r, f)).length,
  });
  const client = {
    startSession: () => session,
    db: () => ({ collection }),
  } as unknown as MongoClient;
  const payload = decodeRuntimeEnvelope(
    rows.tenantWorkflowConfiguration![0],
    key,
    'control',
  );
  const inventory = deriveInventory(payload, scope, 'control');
  const inventoryResolver = new DeletionInventoryResolver(
    client,
    'control',
    key,
    new CredentialVault(Buffer.alloc(32, 9)),
  );
  const store = new MongoDeletionStore(
    client,
    'control',
    key,
    inventoryResolver,
  );
  return {
    rows,
    calls,
    store,
    manifests: [inventory],
    inventoryResolver,
    client,
    key,
    interruptDiscard: () => {
      failDiscard = true;
    },
  };
}
test('native lifecycle preserves runtime fences and final control cleanup is scoped, verified and leaves tombstone', async () => {
  const f = native();
  const service = new DeletionService(f.store, {
    inventory: async () => ({
      complete: true,
      revision: f.manifests[0]!.digest,
      targets: [{ id: 'db', label: 'Database clubdata' }],
    }),
    erase: async () => {},
    absent: async () => true,
  });
  let view = await service.remove(
    scope,
    {
      expectedRevision: 1,
      expectedAuthorityRevision: 1,
      expectedInvitationRevision: 1,
      confirmation: 'development/club',
    },
    'operator',
  );
  assert.equal(f.rows.tenantDefinitions![0]!.writeFence, 8);
  assert.equal(f.rows.tenantDefinitions![0]!.invitationFence, 13);
  const status = await service.purge(
    scope,
    {
      expectedRevision: 2,
      operationId: view.operation!.id,
      expectedOperationRevision: 1,
      expectedInventoryRevision: f.manifests[0]!.digest,
      confirmation: 'development/club',
      completed: checklist.map((x) => x.id),
      allDone: true,
      ownershipConfirmed: true,
      unregisteredResourcesConfirmed: true,
      controlOnly: false,
    },
    'operator',
  );
  assert.equal(status.operation!.phase, 'purged');
  assert.equal(f.rows[snapshotCollection]!.length, 0);
  assert.equal(
    f.rows.tenantDeletionTargets![0]!.operationId,
    status.operation!.id,
  );
  assert.equal(f.rows.tenantRuntimeAuthorities!.length, 0);
  assert.equal(f.rows.tenantExplorerConfiguration!.length, 0);
  assert.equal(f.rows.tenantManagerInvitations!.length, 0);
  assert.equal(f.rows.tenantManagerSetupProofs!.length, 1);
  assert.equal(f.rows.tenantManagerSetupProofs![0]!.environment, 'production');
  assert.equal(f.rows.tenantDefinitions![0]!.public.name, 'Deleted tenant');
  assert.equal(f.rows.tenantExplorerAudit![0]!.actor, 'operator');
  for (const call of f.calls.filter(
    (c) => c.name === 'tenantManagerSetupProofs',
  ))
    assert.deepEqual(call.filter, {
      environment: 'development',
      tenantId: 'club',
    });
});

test('native deletion selects exact environment even when another environment uses the same tenant ID', async () => {
  const f = native();
  const productionDefinition = {
    ...structuredClone(f.rows.tenantDefinitions![0]!),
    environment: 'production',
  };
  f.rows.tenantDefinitions!.push(productionDefinition);
  f.rows.tenantRuntimeAuthorities!.push({
    ...structuredClone(f.rows.tenantRuntimeAuthorities![0]!),
    environment: 'production',
  });
  const service = new DeletionService(f.store, {
    inventory: async () => ({
      complete: false,
      revision: 'unconfigured',
      targets: [],
    }),
    erase: async () => {
      throw Error('must not delete');
    },
    absent: async () => false,
  });
  await service.remove(
    { environment: 'production', tenantId: 'club' },
    {
      expectedRevision: 1,
      expectedAuthorityRevision: 1,
      expectedInvitationRevision: 0,
      confirmation: 'production/club',
    },
    'operator',
  );
  assert.equal(
    f.rows.tenantDefinitions!.find((d) => d.environment === 'development')!
      .status,
    'active',
  );
  assert.equal(
    f.rows.tenantRuntimeAuthorities!.find(
      (d) => d.environment === 'development',
    )!.status,
    'active',
  );
  assert.equal(
    f.rows.tenantDefinitions!.find((d) => d.environment === 'production')!
      .status,
    'disabled',
  );
});

import { Db } from 'mongodb';
test('purger cannot drop a database without the matching durable reservation', async () => {
  const originalConnect = MongoClient.prototype.connect,
    originalClose = MongoClient.prototype.close,
    originalDrop = Db.prototype.dropDatabase;
  let drops = 0;
  MongoClient.prototype.connect = async function () {
    return this;
  };
  MongoClient.prototype.close = async function () {};
  Db.prototype.dropDatabase = async function () {
    drops++;
    return true;
  };
  try {
    await assert.rejects(
      port([{ id: 'club', mongoUri: 'mongodb://localhost/clubdata' }]).erase(
        scope,
        databaseTargetId('mongodb://localhost/clubdata', 'clubdata'),
      ),
      /reservation/i,
    );
    assert.equal(drops, 0);
  } finally {
    MongoClient.prototype.connect = originalConnect;
    MongoClient.prototype.close = originalClose;
    Db.prototype.dropDatabase = originalDrop;
  }
});

import { databaseTargetId } from '../src/database-target.js';
test('connection-time reassignment cannot pass the permanent target reservation and fresh ownership check', async () => {
  const f = native(),
    purger = new MongoPurgePort(
      f.client,
      'control',
      f.key,
      f.inventoryResolver,
    ),
    service = new DeletionService(f.store, purger);
  const view = await service.remove(
    scope,
    {
      expectedRevision: 1,
      expectedAuthorityRevision: 1,
      expectedInvitationRevision: 1,
      confirmation: 'development/club',
    },
    'operator',
  );
  const preview = await purger.inventory(scope);
  const connect = MongoClient.prototype.connect,
    close = MongoClient.prototype.close,
    drop = Db.prototype.dropDatabase;
  let drops = 0;
  MongoClient.prototype.connect = async function () {
    const payload = decodeRuntimeEnvelope(
      f.rows.tenantWorkflowConfiguration![0],
      f.key,
      'control',
    ) as any;
    payload.tenants.push({
      id: 'foreign',
      mongoUri: 'mongodb://localhost/clubdata',
    });
    f.rows.tenantWorkflowConfiguration![0] = encodeRuntimeEnvelope(
      payload,
      f.key,
      'control',
    );
    return this;
  };
  MongoClient.prototype.close = async () => {};
  Db.prototype.dropDatabase = async () => {
    drops++;
    return true;
  };
  try {
    const status = await service.purge(
      scope,
      {
        expectedRevision: 2,
        operationId: view.operation!.id,
        expectedOperationRevision: 1,
        expectedInventoryRevision: preview.revision,
        confirmation: 'development/club',
        completed: checklist.map((x) => x.id),
        allDone: true,
        ownershipConfirmed: true,
        unregisteredResourcesConfirmed: true,
        controlOnly: false,
      },
      'operator',
    );
    assert.equal(status.operation!.phase, 'failed');
    assert.equal(drops, 0);
  } finally {
    MongoClient.prototype.connect = connect;
    MongoClient.prototype.close = close;
    Db.prototype.dropDatabase = drop;
  }
});
test('foreign permanent target reservation blocks purge claim before any database erase', async () => {
  const f = native();
  f.rows.tenantDeletionTargets = [
    {
      _id: databaseTargetId('mongodb://localhost/clubdata', 'clubdata'),
      operationId: 'other-op',
      environment: 'production',
      tenantId: 'other',
      manifestRevision: 'other',
    },
  ];
  let erased = false;
  const service = new DeletionService(f.store, {
    inventory: async () => ({
      complete: true,
      revision: f.manifests[0]!.digest,
      targets: [{ id: 'db', label: 'Database clubdata' }],
    }),
    erase: async () => {
      erased = true;
    },
    absent: async () => true,
  });
  const view = await service.remove(
    scope,
    {
      expectedRevision: 1,
      expectedAuthorityRevision: 1,
      expectedInvitationRevision: 1,
      confirmation: 'development/club',
    },
    'operator',
  );
  await assert.rejects(
    service.purge(
      scope,
      {
        expectedRevision: 2,
        operationId: view.operation!.id,
        expectedOperationRevision: 1,
        expectedInventoryRevision: f.manifests[0]!.digest,
        confirmation: 'development/club',
        completed: checklist.map((x) => x.id),
        allDone: true,
        ownershipConfirmed: true,
        unregisteredResourcesConfirmed: true,
        controlOnly: false,
      },
      'operator',
    ),
    /reserved/i,
  );
  assert.equal(erased, false);
  assert.equal(f.rows.tenantDeletionOperations![0]!.phase, 'retained');
});

test('crash after runtime prune but before final operation commit preserves encrypted targets and retries the same snapshot', async () => {
  const f = native();
  let erases = 0;
  const purger = {
    inventory: async () => {
      const m = await f.inventoryResolver.resolve(scope);
      return {
        complete: true,
        revision: m.digest,
        controlOnly: m.controlOnly,
        targets: m.targets.map((t) => ({
          id: t.id,
          label: `Database ${t.database}`,
        })),
      };
    },
    erase: async () => {
      erases++;
    },
    absent: async () => true,
  };
  const service = new DeletionService(f.store, purger);
  const view = await service.remove(
    scope,
    {
      expectedRevision: 1,
      expectedAuthorityRevision: 1,
      expectedInvitationRevision: 1,
      confirmation: 'development/club',
    },
    'operator',
  );
  const request = (revision: number) => ({
    expectedRevision: 2,
    operationId: view.operation!.id,
    expectedOperationRevision: revision,
    expectedInventoryRevision: f.manifests[0]!.digest,
    confirmation: 'development/club',
    completed: checklist.map((x) => x.id),
    allDone: true,
    ownershipConfirmed: true,
    unregisteredResourcesConfirmed: true,
    controlOnly: false,
  });
  f.interruptDiscard();
  const failed = await service.purge(scope, request(1), 'operator');
  assert.equal(failed.operation!.phase, 'failed');
  assert.equal(f.rows[snapshotCollection]!.length, 1);
  assert.ok(!JSON.stringify(f.rows[snapshotCollection]).includes('mongodb'));
  const pruned = decodeRuntimeEnvelope(
    f.rows.tenantWorkflowConfiguration![0],
    f.key,
    'control',
  ) as any;
  assert.ok(!pruned.tenants.some((t: any) => t.id === 'club'));
  const retry = await service.purge(
    scope,
    request(failed.operation!.revision),
    'operator',
  );
  assert.equal(retry.operation!.phase, 'purged');
  assert.equal(erases, 1);
  assert.equal(f.rows[snapshotCollection]!.length, 0);
  assert.equal(
    f.rows.tenantDeletionTargets![0]!.operationId,
    retry.operation!.id,
  );
});
