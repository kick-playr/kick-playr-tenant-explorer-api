import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { encodeRuntimeEnvelope, decodeRuntimeEnvelope, type RuntimeEnvelope } from '../src/runtime-configuration.js';
import { migrateRuntimeVault, type MigrationStore, type MigrationTargets, type MigrationDefinition } from '../src/maintenance/migrate-runtime-vault.js';

const database = 'test-control';
function fixture() {
  const key = randomBytes(32);
  const payload = { version: 2, tenants: [{ id: 'fcrww', mongoUri: 'mongodb://user:password@cluster.invalid/club', clerkSecret: 'sk_test_fixture', wrappingKeyRef: 'env:EXISTING_WRAPPING_KEY_V1' }, { id: 'other', mongoUri: 'preserve', clerkSecret: 'preserve' }], replayConfig: { url: 'redis://user:password@redis.invalid:6379', tls: false, prefix: 'existing' }, explorer: { preserve: true } };
  let envelope: RuntimeEnvelope | null = encodeRuntimeEnvelope(payload, key, database);
  let definition: MigrationDefinition | null = { id: 'fcrww', environment: 'development', configRevision: 2, status: 'active' };
  const events: string[] = [];
  const store: MigrationStore = {
    readEnvelope: async () => structuredClone(envelope),
    readDefinition: async () => structuredClone(definition),
    compareAndSwap: async (original, next) => { assert.deepEqual(original, envelope); events.push('write'); envelope = next; return true; },
    transaction: async fn => { events.push('transaction'); await fn(store); },
  };
  const targets: MigrationTargets = { sharedScope: { environment: 'development', tenant: '_shared' }, tenantScope: { environment: 'development', tenant: 'fcrww' }, tenantRevision: 2, tenantValues: { MONGODB_URI: payload.tenants[0]!.mongoUri, CLERK_SECRET_KEY: payload.tenants[0]!.clerkSecret }, sharedValues: { REDIS_URL: payload.replayConfig.url } };
  const load = async () => structuredClone(targets);
  const backup = async (row: RuntimeEnvelope) => { assert.deepEqual(row, envelope); events.push('backup'); return '/private/backup.encrypted.json'; };
  const options = { tenant: 'fcrww', database };
  return { key, payload, store, targets, load, backup, options, events, envelope: () => envelope, setEnvelope: (row: RuntimeEnvelope | null) => { envelope = row; }, setDefinition: (row: MigrationDefinition | null) => { definition = row; } };
}

test('default dry-run reports only references and performs no writes or backups', async () => {
  const f = fixture(), before = structuredClone(f.envelope());
  const result = await migrateRuntimeVault(f.store, f.key, f.options, f.load, f.backup);
  assert.equal(result.readyToApply, true); assert.equal(result.applied, false);
  assert.equal(result.checks.filter(c => c.status === 'will-reference').length, 3);
  assert.ok(!JSON.stringify(result).includes('password')); assert.ok(!JSON.stringify(result).includes('sk_test_fixture'));
  assert.deepEqual(f.events, []); assert.deepEqual(f.envelope(), before);
});
test('apply backs up first and changes only the three approved reference fields', async () => {
  const f = fixture(), preview = await migrateRuntimeVault(f.store, f.key, f.options, f.load, f.backup);
  const result = await migrateRuntimeVault(f.store, f.key, { ...f.options, apply: true, expectedDigest: preview.sourceDigest }, f.load, f.backup);
  assert.equal(result.applied, true); assert.deepEqual(f.events, ['backup', 'transaction', 'write']);
  const next = decodeRuntimeEnvelope(f.envelope(), f.key, database) as any;
  assert.equal(next.tenants[0].mongoUri, 'vault:MONGODB_URI'); assert.equal(next.tenants[0].clerkSecret, 'vault:CLERK_SECRET_KEY'); assert.equal(next.replayConfig.url, 'vault:REDIS_URL');
  assert.equal(next.tenants[0].wrappingKeyRef, f.payload.tenants[0]!.wrappingKeyRef);
  assert.deepEqual(next.tenants[1], f.payload.tenants[1]); assert.deepEqual(next.explorer, f.payload.explorer);
  assert.equal(next.replayConfig.prefix, 'existing'); assert.equal(next.replayConfig.tls, false);
});
test('each mismatched target blocks the entire apply without exposing values', async () => {
  for (const field of ['MONGODB_URI', 'CLERK_SECRET_KEY', 'REDIS_URL'] as const) {
    const f = fixture();
    if (field === 'REDIS_URL') f.targets.sharedValues.REDIS_URL = 'redis://different:secret@other.invalid:6379';
    else if (field === 'MONGODB_URI') f.targets.tenantValues.MONGODB_URI = 'mongodb://different:secret@other.invalid/db';
    else f.targets.tenantValues.CLERK_SECRET_KEY = 'sk_test_different';
    const result = await migrateRuntimeVault(f.store, f.key, { ...f.options, apply: true, expectedDigest: 'a'.repeat(64) }, f.load, f.backup);
    assert.equal(result.readyToApply, false); assert.equal(result.applied, false); assert.ok(result.checks.some(c => c.reason === 'VaultValueMismatch'));
    assert.ok(!JSON.stringify(result).includes('different')); assert.deepEqual(f.events, []);
  }
});
test('missing and malformed vault values block migration', async () => {
  for (const value of [undefined, '<existing Redis URL>']) {
    const f = fixture(); f.targets.sharedValues.REDIS_URL = value;
    const result = await migrateRuntimeVault(f.store, f.key, f.options, f.load, f.backup);
    assert.equal(result.readyToApply, false); assert.ok(result.checks.some(c => c.status === 'blocked')); assert.deepEqual(f.events, []);
  }
});
test('wrong tenant namespace or revision refuses all changes', async () => {
  for (const mode of ['scope', 'revision']) {
    const f = fixture(); if (mode === 'scope') f.targets.tenantScope.tenant = 'other'; else f.targets.tenantRevision = 3;
    await assert.rejects(migrateRuntimeVault(f.store, f.key, f.options, f.load, f.backup)); assert.deepEqual(f.events, []);
  }
});
test('missing and deleted tenant definitions cannot be migrated', async () => {
  for (const mode of ['missing', 'deleted']) {
    const f = fixture(); f.setDefinition(mode === 'missing' ? null : { id: 'fcrww', environment: 'development', configRevision: 2, status: 'disabled', deletionId: 'deleted' });
    await assert.rejects(migrateRuntimeVault(f.store, f.key, f.options, f.load, f.backup)); assert.deepEqual(f.events, []);
  }
});
test('stale digest or failed backup prevents database mutation', async () => {
  for (const mode of ['digest', 'backup']) {
    const f = fixture(), preview = await migrateRuntimeVault(f.store, f.key, f.options, f.load, f.backup);
    await assert.rejects(migrateRuntimeVault(f.store, f.key, { ...f.options, apply: true, expectedDigest: mode === 'digest' ? '0'.repeat(64) : preview.sourceDigest }, f.load, async () => { throw Error('BackupFailed'); })); assert.deepEqual(f.events, []);
  }
});
test('concurrent envelope, tenant revision and CAS conflicts prevent replacement', async () => {
  for (const mode of ['envelope', 'definition', 'cas']) {
    const f = fixture(), preview = await migrateRuntimeVault(f.store, f.key, f.options, f.load, f.backup);
    if (mode === 'cas') f.store.compareAndSwap = async () => false;
    await assert.rejects(migrateRuntimeVault(f.store, f.key, { ...f.options, apply: true, expectedDigest: preview.sourceDigest }, f.load, async row => {
      if (mode === 'envelope') f.setEnvelope(encodeRuntimeEnvelope(f.payload, f.key, database));
      if (mode === 'definition') f.setDefinition({ id: 'fcrww', environment: 'development', configRevision: 3, status: 'active' });
      return '/backup';
    })); assert.ok(!f.events.includes('write'));
  }
});
test('idempotent repeat makes no new backup or write', async () => {
  const f = fixture(), preview = await migrateRuntimeVault(f.store, f.key, f.options, f.load, f.backup);
  await migrateRuntimeVault(f.store, f.key, { ...f.options, apply: true, expectedDigest: preview.sourceDigest }, f.load, f.backup); f.events.length = 0;
  const result = await migrateRuntimeVault(f.store, f.key, { ...f.options, apply: true }, f.load, f.backup);
  assert.equal(result.applied, false); assert.equal(result.readyToApply, true); assert.ok(result.checks.every(c => c.status === 'already-referenced')); assert.deepEqual(f.events, []);
});
test('conflicting references and duplicate tenant runtime entries are not silently rewritten', async () => {
  for (const mode of ['reference', 'duplicate']) {
    const f = fixture(); const payload = structuredClone(f.payload);
    if (mode === 'reference') payload.tenants[0]!.mongoUri = 'vault:OTHER_MAPPING'; else payload.tenants.push(structuredClone(payload.tenants[0]!));
    f.setEnvelope(encodeRuntimeEnvelope(payload, f.key, database));
    if (mode === 'duplicate') await assert.rejects(migrateRuntimeVault(f.store, f.key, f.options, f.load, f.backup));
    else { const result = await migrateRuntimeVault(f.store, f.key, f.options, f.load, f.backup); assert.equal(result.readyToApply, false); }
    assert.deepEqual(f.events, []);
  }
});
test('missing configuration and wrong decryption key cannot cause side effects', async () => {
  for (const mode of ['missing', 'key']) {
    const f = fixture(); if (mode === 'missing') f.setEnvelope(null);
    await assert.rejects(migrateRuntimeVault(f.store, mode === 'key' ? randomBytes(32) : f.key, f.options, f.load, f.backup)); assert.deepEqual(f.events, []);
  }
});
test('an explicit other environment or conflicting runtime tenant identity is refused', async () => {
  for (const extra of [{ environment: 'production' }, { tenantId: 'other' }]) {
    const f = fixture(), payload = structuredClone(f.payload);
    Object.assign(payload.tenants[0]!, extra);
    f.setEnvelope(encodeRuntimeEnvelope(payload, f.key, database));
    await assert.rejects(migrateRuntimeVault(f.store, f.key, f.options, f.load, f.backup), /RuntimeScopeMismatch/);
    assert.deepEqual(f.events, []);
  }
});
test('migration help and argument refusals need no credentials or network', () => {
  const args = ['--import', 'tsx', 'src/maintenance/migrate-runtime-vault-cli.ts'];
  const output = execFileSync(process.execPath, [...args, '--help'], { env: { PATH: process.env.PATH }, encoding: 'utf8' });
  assert.match(output, /Dry-run by default/); assert.match(output, /--expect-digest/);
  const result = spawnSync(process.execPath, [...args, '--tenant', 'fcrww', '--apply'], { env: { PATH: process.env.PATH }, encoding: 'utf8' });
  assert.equal(result.status, 1); assert.match(result.stderr, /ApplyRequiresReviewedDigest/);
});
