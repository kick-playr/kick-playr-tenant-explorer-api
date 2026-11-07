import test from 'node:test';
import assert from 'node:assert/strict';
import { createV2IntegrationAdmission } from '../src/v2-integration-admission.js';

// The admission reader never asks MongoDB for encrypted or plaintext token values.
test('v2 admission binds static memory to the tenant native authority metadata', async () => {
  let row: Record<string, unknown> = {
    _id: 'development/resource-bexio', tenantId: 'club', environment: 'development',
    integrationId: 'resource-bexio', staticVersion: 'v3', accountReference: 'account',
    status: 'active', operation: null, revision: 4, authorityGeneration: 2,
  };
  let reads = 0;
  let schemaIdentity = 'builtin:bexio@1';
  const admit = createV2IntegrationAdmission({
    integration: () => ({ resourceId: 'resource-bexio', versionId: 'v3', kind: 'integration', schemaIdentity, value: { accountReference: 'account' } }),
    readAuthority: async (definition, id) => {
      assert.equal(definition.id, 'club'); assert.equal(id, 'resource-bexio');
      reads++; return row;
    },
  });
  const definition = { id: 'club', environment: 'development' } as never;
  const connection = { provider: 'bexio', credentialId: 'bexio', accountReference: 'account', enabled: true } as never;
  await admit(definition, 'bexio', connection);
  assert.equal(reads, 1);
  for (const wrongSchema of ['builtin:dropbox@1', 'builtin:email@1', 'custom:bexio@1', 'builtin:bexio@2']) {
    schemaIdentity = wrongSchema;
    await assert.rejects(admit(definition, 'bexio', connection));
  }
  assert.equal(reads, 1);
  schemaIdentity = 'builtin:bexio@1';
  for (const patch of [
    { tenantId: 'other' }, { environment: 'production' }, { integrationId: 'other' },
    { staticVersion: 'old' }, { accountReference: 'other' }, { status: 'revoked' },
    { operation: { phase: 'dispatched' } }, { authorityGeneration: 0 }, { revision: 0 },
  ]) {
    const previous = row; row = { ...row, ...patch };
    await assert.rejects(admit(definition, 'bexio', connection), /active native runtime authority/);
    row = previous;
  }
  await assert.rejects(admit(definition, 'bexio', { ...connection as object, accountReference: 'other' } as never));
});

test('native metadata reader pins tenant database, excludes credentials, and closes its connection', async () => {
  const { nativeAuthorityReader } = await import('../src/v2-integration-admission.js');
  let closed = 0;
  let configuredUri = 'mongodb://fixture';
  let fail = false;
  const read = nativeAuthorityReader({ secret: (identity: { tenantId: string }, reference: unknown) => {
    assert.equal(identity.tenantId, 'club');
    assert.equal(reference, 'vault:MONGODB_URI');
    return configuredUri;
  } } as never, ((uri: string) => {
    assert.equal(uri, configuredUri);
    return {
      connect: async () => {}, close: async () => { closed++; },
      db: (database: string) => {
        assert.equal(database, 'club-kick-playr');
        return { collection: (collection: string) => {
          assert.equal(collection, 'integration_runtime_credentials');
          return { findOne: async (filter: unknown, options: { projection: Record<string, number> }) => {
            assert.deepEqual(filter, { _id: 'development/resource', tenantId: 'club', environment: 'development', integrationId: 'resource' });
            assert.deepEqual(Object.keys(options.projection).sort(), ['_id', 'accountReference', 'authorityGeneration', 'environment', 'integrationId', 'operation', 'revision', 'staticVersion', 'status', 'tenantId']);
            assert.ok(Object.values(options.projection).every(v => v === 1));
            if (fail) throw Error('read failed');
            return null;
          } };
        } };
      },
    };
  }) as never);
  const definition = { id: 'club', environment: 'development', configRevision: 2, secretReferences: { mongoUri: 'vault:MONGODB_URI' } } as never;
  assert.equal(await read(definition, 'resource'), null);
  configuredUri = 'mongodb://fixture/club-kick-playr';
  assert.equal(await read(definition, 'resource'), null);
  fail = true;
  await assert.rejects(read(definition, 'resource'), /read failed/);
  assert.equal(closed, 3);
});


test('invalid native scope is rejected before secrets lookup or client construction', async () => {
  const { nativeAuthorityReader } = await import('../src/v2-integration-admission.js');
  let lookups = 0, opens = 0;
  const read = nativeAuthorityReader({ secret: () => { lookups++; return 'mongodb://fixture'; } } as never,
    (() => { opens++; throw Error('client must not open'); }) as never);
  for (const id of ['control', 'key-vault', 'a'.repeat(53), 'club-', 'Club', '../club', '']) {
    await assert.rejects(read({ id, environment: 'development', secretReferences: { mongoUri: 'vault:MONGODB_URI' } } as never, 'resource'));
  }
  for (const environment of ['', 'Production', 'a'.repeat(33), 'development/other']) {
    await assert.rejects(read({ id: 'club', environment, secretReferences: { mongoUri: 'vault:MONGODB_URI' } } as never, 'resource'));
  }
  assert.equal(lookups, 0);
  assert.equal(opens, 0);
});


test('native metadata rejects conflicting explicit URI database before opening Mongo', async () => {
  const { nativeAuthorityReader } = await import('../src/v2-integration-admission.js');
  let opens = 0;
  const read = nativeAuthorityReader({ secret: () => 'mongodb://fixture/control-kick-playr' } as never,
    (() => { opens++; throw Error('must not open'); }) as never);
  await assert.rejects(read({ id: 'club', environment: 'development', configRevision: 1,
    secretReferences: { mongoUri: 'vault:MONGODB_URI' } } as never, 'resource'));
  assert.equal(opens, 0);
});

test('static email and Pingen admission uses only the pinned tenant resource', async () => {
  let reads = 0;
  let resource = { resourceId: 'resource-static', versionId: 'v2', kind: 'integration',
    schemaIdentity: 'builtin:email@1', value: { protocol: 'smtp', username: 'mail@example.test' } as Record<string, unknown> };
  const admit = createV2IntegrationAdmission({ integration: (definition, reference) => {
    assert.equal(definition.id, 'club'); assert.equal(reference, 'static-reference'); return resource;
  }, readAuthority: async () => { reads++; throw Error('static providers must not read runtime tokens'); } });
  const definition = { id: 'club', environment: 'development' } as never;
  const connection = { credentialId: 'static-reference', provider: 'smtp', accountReference: 'club-smtp', capabilities: [], enabled: true };
  await admit(definition, 'mail', connection as never);
  await assert.rejects(admit(definition, 'mail', { ...connection, provider: 'imap' } as never));
  resource = { ...resource, value: { protocol: 'imap', username: 'mail@example.test' } };
  await assert.rejects(admit(definition, 'mail', { ...connection, provider: 'imap' } as never));
  resource = { ...resource, schemaIdentity: 'builtin:email@2', value: { ...resource.value, inboxFolder: 'INBOX', archiveFolder: 'Archive' } };
  await admit(definition, 'mail', { ...connection, provider: 'imap', accountReference: 'club-imap' } as never);
  resource = { ...resource, schemaIdentity: 'builtin:pingen@1', value: { apiToken: 'static-api-token', organizationId: 'org' } };
  await admit(definition, 'post', { ...connection, provider: 'pingen', accountReference: 'club-pingen' } as never);
  await assert.rejects(admit(definition, 'mail', connection as never));
  resource = { ...resource, schemaIdentity: 'builtin:pingen@2', value: { webhookSecret: 'static-webhook' } };
  await admit(definition, 'events', { ...connection, provider: 'pingen', capabilities: ['letters:events'] } as never);
  await assert.rejects(admit(definition, 'post', { ...connection, provider: 'pingen', capabilities: ['letters:send'] } as never));
  assert.equal(reads, 0);
});
