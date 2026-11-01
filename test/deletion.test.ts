import 'reflect-metadata';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  recoveryDeadline,
  checklist,
  parseManifests,
} from '../src/deletion/contracts.js';
import { DeletionService } from '../src/deletion/service.js';
import type {
  DeletionState,
  DeletionStore,
  Scope,
  PurgePort,
} from '../src/deletion/contracts.js';

const scope: Scope = { environment: 'development', tenantId: 'club' };
function fixture() {
  let now = Date.parse('2026-11-01T12:00:00Z');
  let state: DeletionState = {
    tenant: {
      definition: {
        id: 'club',
        environment: 'development',
        status: 'active',
        configRevision: 1,
        hostname: 'club.ch',
        aliases: [],
        public: { name: 'Club', locale: 'de-CH' },
        secretReferences: { mongoUri: 'ref:mongo', key: 'ref:key' },
      },
      authority: {
        schema: 1,
        tenantId: 'club',
        environment: 'development',
        status: 'active',
        configRevision: 1,
        authorityRevision: 1,
        supportRevision: 1,
        identityRealm: 'https://clerk.example',
        hostnames: ['club.ch'],
        users: [
          {
            issuer: 'https://clerk.example',
            subject: 'u',
            revision: 1,
            status: 'active',
            contactId: 1,
            permissions: [],
          },
        ],
        services: [{ status: 'active', revision: 1 }],
      },
      metadata: { configuration: {}, credentials: [], integrations: [] },
    },
    invitations: {
      revision: 1,
      principals: [
        {
          id: 'p',
          issuer: 'i',
          subject: 'u',
          state: 'operational',
          role: 'owner',
        },
      ],
      invitations: [],
    },
  };
  const events: string[] = [];
  let queue = Promise.resolve();
  const store: DeletionStore = {
    transact: async (s, work) => {
      assert.deepEqual(s, scope);
      const previous = queue;
      let release!: () => void;
      queue = new Promise<void>((r) => {
        release = r;
      });
      await previous;
      const copy = structuredClone(state);
      try {
        const result = await work(copy, { reserveTargets: async () => {} });
        state = copy;
        return structuredClone(result);
      } finally {
        release();
      }
    },
    finish: async (s, id, lease) => {
      assert.equal(state.operation?.id, id);
      assert.equal(state.operation?.leaseId, lease);
      events.push('control');
      state.tenant.metadata = {
        configuration: {},
        credentials: [],
        integrations: [],
      };
    },
  };
  let fail = false,
    verify = true,
    complete = true,
    active = 0,
    maxActive = 0;
  const port: PurgePort = {
    inventory: async () => ({
      revision: 'manifest-v1',
      complete,
      targets: [{ id: 'operational', label: 'Operational database' }],
    }),
    erase: async () => {
      active++;
      maxActive = Math.max(active, maxActive);
      await Promise.resolve();
      events.push('erase');
      active--;
      if (fail) throw Error('fixture secret');
    },
    absent: async () => verify,
  };
  const service = new DeletionService(store, port, () => now);
  const soft = () =>
    service.remove(
      scope,
      {
        expectedRevision: 1,
        expectedAuthorityRevision: 1,
        expectedInvitationRevision: 1,
        confirmation: 'development/club',
      },
      'operator',
    );
  const purge = () =>
    service.purge(
      scope,
      {
        expectedRevision: state.tenant.definition.configRevision,
        operationId: state.operation!.id,
        expectedOperationRevision: state.operation!.revision,
        expectedInventoryRevision: 'manifest-v1',
        confirmation: 'development/club',
        completed: checklist.map((x) => x.id),
        allDone: true,
      },
      'operator',
    );
  return {
    service,
    soft,
    purge,
    events,
    get state() {
      return state;
    },
    set now(v: number) {
      now = v;
    },
    set fail(v: boolean) {
      fail = v;
    },
    set verify(v: boolean) {
      verify = v;
    },
    set complete(v: boolean) {
      complete = v;
    },
    get maxActive() {
      return maxActive;
    },
  };
}
test('calendar retention clamps month end and preserves Zurich local time through DST', () => {
  assert.equal(
    recoveryDeadline('2026-11-30T11:00:00Z'),
    '2027-02-28T11:00:00.000Z',
  );
  assert.equal(
    recoveryDeadline('2026-01-31T11:00:00Z'),
    '2026-04-30T10:00:00.000Z',
  );
});
test('soft delete atomically blocks authority and revokes users, services and invitation principals', async () => {
  const f = fixture();
  await f.soft();
  assert.equal(f.state.tenant.definition.status, 'disabled');
  assert.equal(f.state.tenant.definition.deletionId, f.state.operation?.id);
  assert.equal(f.state.tenant.authority?.users[0]?.status, 'revoked');
  assert.equal(
    (f.state.tenant.authority?.services[0] as any).status,
    'revoked',
  );
  assert.equal(f.state.invitations?.principals[0]?.state, 'revoked');
  assert.equal(f.state.operation?.phase, 'retained');
  await assert.rejects(f.soft(), /revision|changed/);
});
test('recovery to disabled requires fresh grants and cannot occur at deadline or after purge latch', async () => {
  const f = fixture();
  await f.soft();
  const op = f.state.operation!;
  f.now = Date.parse(op.recoverUntil);
  await assert.rejects(
    f.service.recover(
      scope,
      {
        expectedRevision: 2,
        operationId: op.id,
        expectedOperationRevision: f.state.operation!.revision,
        confirmation: 'development/club',
      },
      'operator',
    ),
    /recovery/i,
  );
  f.now = Date.parse('2026-11-02');
  await f.service.recover(
    scope,
    {
      expectedRevision: 2,
      operationId: op.id,
      expectedOperationRevision: f.state.operation!.revision,
      confirmation: 'development/club',
    },
    'operator',
  );
  assert.equal(f.state.tenant.definition.status, 'disabled');
  assert.equal(f.state.tenant.definition.deletionId, undefined);
  assert.equal(f.state.tenant.authority?.users[0]?.status, 'revoked');
});
test('purge requires complete inventory and final checklist, cannot recover after failed deletion, retry verifies same targets', async () => {
  const f = fixture();
  await f.soft();
  f.complete = false;
  await assert.rejects(f.purge(), /inventory/i);
  f.complete = true;
  f.fail = true;
  await f.purge();
  assert.equal(f.state.operation?.phase, 'failed');
  assert.ok(!JSON.stringify(f.state.operation).includes('fixture secret'));
  await assert.rejects(
    f.service.recover(
      scope,
      {
        expectedRevision: 2,
        operationId: f.state.operation!.id,
        expectedOperationRevision: f.state.operation!.revision,
        confirmation: 'development/club',
      },
      'o',
    ),
    /recovery/i,
  );
  f.fail = false;
  await f.purge();
  assert.equal(f.state.operation?.phase, 'purged');
  assert.deepEqual(f.events, ['erase', 'erase', 'control']);
});
test('absence verification failures remain failed; duplicate concurrent requests cannot delete concurrently', async () => {
  const f = fixture();
  await f.soft();
  f.verify = false;
  await f.purge();
  assert.equal(f.state.operation?.phase, 'failed');
  f.verify = true;
  await Promise.allSettled([f.purge(), f.purge()]);
  assert.equal(f.state.operation?.phase, 'purged');
  assert.equal(f.maxActive, 1);
});
test('wrong environment/tenant confirmation and unchecked checklist are rejected', async () => {
  const f = fixture();
  await assert.rejects(
    f.service.remove(
      scope,
      {
        expectedRevision: 1,
        expectedAuthorityRevision: 1,
        expectedInvitationRevision: 1,
        confirmation: 'production/club',
      },
      'o',
    ),
    /confirmation/i,
  );
  await f.soft();
  await assert.rejects(
    f.service.purge(
      scope,
      {
        expectedRevision: 2,
        operationId: f.state.operation!.id,
        expectedOperationRevision: f.state.operation!.revision,
        expectedInventoryRevision: 'manifest-v1',
        confirmation: 'development/club',
        completed: [],
        allDone: true,
      },
      'o',
    ),
    /checklist/i,
  );
});
test('manifest rejects shared database targets and protected databases', () => {
  const entry = {
    environment: 'development',
    tenantId: 'club',
    complete: true,
    revision: 'one',
    targets: [
      {
        id: 'db',
        connectionVariable: 'CLUB_DB_URI',
        database: 'operational',
        exclusive: true,
        evidence: 'inventory approved',
      },
    ],
    scopedCollections: [],
  };
  assert.throws(
    () =>
      parseManifests(
        [entry, { ...entry, tenantId: 'other' }],
        { CLUB_DB_URI: 'mongodb://localhost/operational' },
        'control',
      ),
    /shared/i,
  );
  assert.throws(
    () =>
      parseManifests(
        [{ ...entry, targets: [{ ...entry.targets[0], database: 'admin' }] }],
        { CLUB_DB_URI: 'mongodb://localhost/operational' },
        'control',
      ),
    /protected/i,
  );
});
test('active delivery lease blocks purge even after invitations were revoked', async () => {
  const f = fixture();
  f.state.invitations!.invitations.push({
    id: 'invite',
    tokenHash: 'hash',
    version: 1,
    expectedIssuer: 'i',
    recipient: { kind: 'email', email: 'test@example.invalid' },
    email: 'test@example.invalid',
    inviter: 'o',
    expiresAt: Date.now() + 60000,
    state: 'pending',
    bootstrap: false,
    delivery: {
      status: 'sending',
      attempts: 1,
      leaseUntil: Date.parse('2026-11-01T12:01:00Z'),
    },
  });
  await f.soft();
  await assert.rejects(f.purge(), /delivery/i);
  assert.equal(f.events.length, 0);
});
test('stale inventory and operation revisions block deletion before any target I/O', async () => {
  const f = fixture();
  await f.soft();
  const body = {
    expectedRevision: 2,
    operationId: f.state.operation!.id,
    expectedOperationRevision: 1,
    expectedInventoryRevision: 'old',
    confirmation: 'development/club',
    completed: checklist.map((x) => x.id),
    allDone: true,
  };
  await assert.rejects(f.service.purge(scope, body, 'o'), /changed/i);
  assert.equal(f.events.length, 0);
});

test('soft deletion rejects an invitation impact revision that changed after preview', async () => {
  const f = fixture();
  f.state.invitations!.revision = 2;
  await assert.rejects(f.soft(), /changed/i);
  assert.equal(f.state.tenant.definition.status, 'active');
});
test('Zurich spring-forward recovery deadline uses the next valid wall time', () => {
  assert.equal(
    recoveryDeadline('2026-12-28T01:30:00Z'),
    '2027-03-28T01:30:00.000Z',
  );
});
