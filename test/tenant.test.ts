import 'reflect-metadata';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TenantService } from '../src/tenant.service.js';
import { CredentialVault } from '../src/vault.js';
import { MemoryRepository } from './memory-repository.js';

const actor = 'user_platform_operator';
const input = (id = 'winikon') => ({
  id,
  environment: 'development',
  hostname: `${id}.localhost:4311`,
  aliases: [],
  public: { name: id, locale: 'de-CH' },
  secretReferences: { mongoUri: `local:${id}:mongo`, key: `local:${id}:key` },
  identityRealm: 'https://example.clerk.accounts.dev',
});
function fixture() {
  const repository = new MemoryRepository();
  const vault = new CredentialVault(Buffer.alloc(32, 7));
  return { repository, vault, service: new TenantService(repository, vault) };
}

test('creates a provisioning tenant with coherent domains and runtime authority', async () => {
  const { service, repository } = fixture();
  const result = await service.create(input(), actor);
  assert.equal(result.status, 'provisioning');
  assert.equal(result.configRevision, 1);
  assert.equal((await service.list({ page: 1, pageSize: 20 })).total, 1);
  const saved = await repository.read('development', 'winikon');
  assert.equal(saved?.authority?.status, 'disabled');
  assert.deepEqual(saved?.authority?.hostnames, ['winikon.localhost:4311']);
  assert.equal(saved?.authority?.configRevision, 1);
});

test('rejects conflicting domains without partially creating a tenant', async () => {
  const { service } = fixture();
  await service.create(input(), actor);
  await assert.rejects(
    service.create(
      { ...input('uster'), aliases: ['winikon.localhost:4311'] },
      actor,
    ),
    /domain|host/i,
  );
  assert.equal((await service.list({ page: 1, pageSize: 20 })).total, 1);
});

test('normalizes domain case and allows the same host in a different environment', async () => {
  const { service } = fixture();
  const a = await service.create(
    { ...input(), hostname: 'APP.Example.ch' },
    actor,
  );
  assert.equal(a.hostname, 'app.example.ch');
  await service.create(
    {
      ...input('uster'),
      environment: 'production',
      hostname: 'app.example.ch',
    },
    actor,
  );
  assert.equal((await service.list({ page: 1, pageSize: 20 })).total, 2);
});

test('stale concurrent saves cannot overwrite lifecycle or domain changes', async () => {
  const { service, repository } = fixture();
  await service.create(input(), actor);
  await service.update(
    'development',
    'winikon',
    { expectedRevision: 1, status: 'active', hostname: 'club.localhost:4311' },
    actor,
  );
  await assert.rejects(
    service.update(
      'development',
      'winikon',
      { expectedRevision: 1, status: 'disabled' },
      actor,
    ),
    /changed|revision|reload/i,
  );
  const saved = await repository.read('development', 'winikon');
  assert.equal(saved?.definition.status, 'active');
  assert.equal(saved?.authority?.configRevision, 2);
  assert.equal(saved?.authority?.authorityRevision, 2);
  assert.deepEqual(saved?.authority?.hostnames, ['club.localhost:4311']);
});

test('user changes increment grant generations and revoke instead of deleting history', async () => {
  const { service, repository } = fixture();
  await service.create(input(), actor);
  const user = {
    issuer: input().identityRealm,
    subject: 'user_member',
    contactId: 23,
    permissions: ['club:teams:read'],
    status: 'active',
  };
  let view = await service.putUser(
    'development',
    'winikon',
    'user_member',
    { expectedRevision: 1, ...user },
    actor,
  );
  assert.equal(view.users[0]?.revision, 1);
  view = await service.revokeUser(
    'development',
    'winikon',
    'user_member',
    { expectedRevision: 2 },
    actor,
  );
  assert.equal(view.users[0]?.status, 'revoked');
  assert.equal(view.users[0]?.revision, 2);
  assert.equal(
    (await repository.read('development', 'winikon'))?.authority
      ?.authorityRevision,
    3,
  );
  await assert.rejects(
    service.putUser(
      'development',
      'winikon',
      'user_member',
      { ...user, expectedRevision: 3, permissions: ['platform:admin'] },
      actor,
    ),
  );
});

test('credentials are encrypted with tenant binding and never returned or audited', async () => {
  const { service, repository, vault } = fixture();
  await service.create(input(), actor);
  const view = await service.putCredential(
    'development',
    'winikon',
    'smtp-primary',
    {
      expectedRevision: 1,
      label: 'SMTP password',
      value: 'sensitive-secret-value',
    },
    actor,
  );
  const raw = await repository.read('development', 'winikon');
  assert.ok(raw?.metadata.credentials[0]?.envelope);
  assert.ok(!JSON.stringify(raw).includes('sensitive-secret-value'));
  assert.ok(!JSON.stringify(view).includes('ciphertext'));
  assert.ok(!JSON.stringify(view).includes('sensitive-secret-value'));
  const envelope = raw!.metadata.credentials[0]!.envelope!;
  assert.equal(
    vault.open('development/winikon/smtp-primary', envelope),
    'sensitive-secret-value',
  );
  assert.throws(() => vault.open('development/uster/smtp-primary', envelope));
  assert.ok(
    !JSON.stringify(await service.audit('development', 'winikon')).includes(
      'sensitive-secret-value',
    ),
  );
  const revoked = await service.revokeCredential(
    'development',
    'winikon',
    'smtp-primary',
    { expectedRevision: 2 },
    actor,
  );
  assert.equal(revoked.credentials[0]?.status, 'revoked');
  assert.equal(
    (await repository.read('development', 'winikon'))?.metadata.credentials[0]
      ?.envelope,
    undefined,
  );
});

test('enabled integrations require an active credential and block its revocation', async () => {
  const { service } = fixture();
  await service.create(input(), actor);
  const connection = {
    expectedRevision: 1,
    provider: 'smtp',
    label: 'Club mail',
    accountReference: 'mailbox-1',
    capabilities: ['mail:send'],
    credentialId: 'smtp-primary',
    enabled: true,
  };
  await assert.rejects(
    service.putIntegration('development', 'winikon', 'mail', connection, actor),
    /credential/i,
  );
  await service.putCredential(
    'development',
    'winikon',
    'smtp-primary',
    { expectedRevision: 1, label: 'SMTP', value: 'password' },
    actor,
  );
  const result = await service.putIntegration(
    'development',
    'winikon',
    'mail',
    { ...connection, expectedRevision: 2 },
    actor,
  );
  assert.equal(result.integrations[0]?.enabled, true);
  await assert.rejects(
    service.revokeCredential(
      'development',
      'winikon',
      'smtp-primary',
      { expectedRevision: 3 },
      actor,
    ),
    /disable/i,
  );
});

test('rejects reserved hosts, duplicate aliases, unknown fields and inline configuration secrets', async () => {
  const { service } = fixture();
  for (const malformed of [
    { ...input(), unknown: true },
    { ...input(), hostname: 'https://club.ch' },
    { ...input(), aliases: ['winikon.localhost:4311'] },
    { ...input(), environment: 'production', hostname: 'kick-playr.ch' },
    {
      ...input(),
      secretReferences: { mongoUri: 'mongodb://private', key: 'key' },
    },
  ])
    await assert.rejects(service.create(malformed, actor));
  await service.create(input(), actor);
  await assert.rejects(
    service.update(
      'development',
      'winikon',
      { expectedRevision: 1, configuration: { smtp: { password: 'secret' } } },
      actor,
    ),
    /credential|secret/i,
  );
});

test('pagination/filtering and environment identity cannot cross tenant boundaries', async () => {
  const { service } = fixture();
  await service.create(input(), actor);
  await service.create(input('uster'), actor);
  const result = await service.list({ page: 1, pageSize: 1, search: 'uster' });
  assert.equal(result.total, 1);
  assert.equal(result.items[0]?.id, 'uster');
  await assert.rejects(service.get('production', 'uster'), /not found/i);
});

test('cannot change the issuer while retained grants would violate the runtime contract', async () => {
  const { service } = fixture();
  await service.create(input(), actor);
  await service.putUser(
    'development',
    'winikon',
    'user_member',
    {
      expectedRevision: 1,
      issuer: input().identityRealm,
      subject: 'user_member',
      contactId: 23,
      permissions: [],
      status: 'active',
    },
    actor,
  );
  await service.revokeUser(
    'development',
    'winikon',
    'user_member',
    { expectedRevision: 2 },
    actor,
  );
  await assert.rejects(
    service.update(
      'development',
      'winikon',
      {
        expectedRevision: 3,
        identityRealm: 'https://other.clerk.accounts.dev',
      },
      actor,
    ),
    /grant|migration/i,
  );
});
