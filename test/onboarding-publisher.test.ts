import test from 'node:test';
import assert from 'node:assert/strict';
import { publishManagerRuntime } from '../src/onboarding/publisher.js';
test('publisher fences encrypted source generations and atomically writes authority in caller transaction', async () => {
  const writes: { name: string; operation: string; options: unknown }[] = [];
  const session = {};
  const principal = {
    id: 'member',
    issuer: 'https://club.example',
    subject: 'user_owner',
    role: 'owner' as const,
    state: 'setup-only' as const,
  };
  const definition = {
    id: 'club',
    environment: 'development',
    status: 'provisioning',
    configRevision: 1,
    secretReferences: {
      mongoUri: 'workflow-local:club:mongo',
      key: 'workflow-local:club:key',
    },
  };
  const authority = {
    schema:1,
    configRevision: 1,
    authorityRevision: 2,
    supportRevision: 2,
    identityRealm: principal.issuer,
    status: 'disabled',
    users: [],
  };
  let current = true;
  const proof = {
    _id: 'proof',
    version: 1,
    environment: 'development',
    tenantId: 'club',
    membershipId: 'member',
    issuer: principal.issuer,
    subject: principal.subject,
    contactId: 42,
    accountReference: 'account',
    configRevision: 1,
    mongoReference: definition.secretReferences.mongoUri,
    expiresAt: Date.now() + 60000,
    sources: [
      {
        database: 'club-db',
        collection: 'settings',
        expected: { id: 42, hash: 'h', envelope: { ciphertext: 'old' } },
        replacement: { id: 42, hash: 'h', envelope: { ciphertext: 'new' } },
      },
      {
        database: 'club-db',
        collection: 'integration_sessions',
        expected: {
          id: 'bexio',
          revision: 'v',
          envelope: { ciphertext: 'old' },
        },
        replacement: {
          id: 'bexio',
          revision: 'v',
          envelope: { ciphertext: 'new' },
        },
      },
    ],
  };
  const client = {
    db: (database: string) => ({
      collection: (name: string) => ({
        findOne: async () => proof,
        replaceOne: async (_f: unknown, _v: unknown, options: unknown) => {
          writes.push({ name, operation: 'replace', options });
          return { matchedCount: current ? 1 : 0 };
        },
        updateOne: async (_f: unknown, _v: unknown, options: unknown) => {
          writes.push({ name, operation: 'update', options });
          return { matchedCount: 1 };
        },
      }),
    }),
  };
  const input = {
    proofId: 'proof',
    membershipId: 'member',
    issuer: principal.issuer,
    subject: principal.subject,
    contactId: 42,
    accountReference: 'account',
    role: 'owner' as const,
  };
  await publishManagerRuntime(
    client as never,
    'control',
    session as never,
    definition as never,
    authority as never,
    {
      revision: 1,
      invitations: [],
      principals: [principal],
      owner: { issuer: principal.issuer, subject: principal.subject },
    },
    input,
  );
  assert.equal(writes.filter((w) => w.operation === 'replace').length, 2);
  assert.ok(writes.some((w) => w.name === 'tenantRuntimeAuthorities'));
  assert.ok(
    writes.every(
      (w) => (w.options as { session: unknown }).session === session,
    ),
  );
  current = false;
  writes.length = 0;
  await assert.rejects(
    publishManagerRuntime(
      client as never,
      'control',
      session as never,
      definition as never,
      authority as never,
      {
        revision: 1,
        invitations: [],
        principals: [principal],
        owner: { issuer: principal.issuer, subject: principal.subject },
      },
      input,
    ),
  );
  assert.equal(
    writes.some((w) => w.name === 'tenantRuntimeAuthorities'),
    false,
  );
});
