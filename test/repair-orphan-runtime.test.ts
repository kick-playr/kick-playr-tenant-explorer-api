import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtemp, readFile, stat, rm, mkdir, chmod, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { encodeRuntimeEnvelope, decodeRuntimeEnvelope, type RuntimeEnvelope } from '../src/runtime-configuration.js';
import { repairOrphanRuntime, parseRepairArguments, type RepairStore } from '../src/maintenance/repair-orphan-runtime.js';
import { writeEncryptedBackup } from '../src/maintenance/repair-orphan-runtime-cli.js';

const database = 'test-control';
function fixture() {
  const key = randomBytes(32);
  const payload = {
    version: 2,
    profile: 'workflow-real',
    shared: { preserve: 'shared-value' },
    tenants: [{ id: 'fcrww', secret: 'keep' }, { id: 'fcuster', secret: 'remove' }],
    pendingMongoBindings: [{ tenantId: 'fcuster' }, { tenantId: 'other' }],
    explorer: {
      clubRuntimes: [{ tenantId: 'fcuster', environment: 'development' }, { tenantId: 'fcuster', environment: 'test' }],
      setupRuntimes: [{ tenantId: 'fcrww', environment: 'development' }],
      keyBindings: { version: 1, bindings: [{ tenantId: 'fcuster', environment: 'development' }, { tenantId: 'fcrww', environment: 'development' }] },
      unrelated: { preserve: true },
    },
  };
  let envelope: RuntimeEnvelope | null = encodeRuntimeEnvelope(payload, key, database);
  let registered = false;
  const events: string[] = [];
  const store: RepairStore = {
    readEnvelope: async () => structuredClone(envelope),
    hasTenantDefinition: async () => registered,
    compareAndSwap: async (original, next) => { events.push('write'); assert.deepEqual(envelope, original); envelope = next; return true; },
    transaction: async fn => { events.push('transaction'); await fn(store); },
  };
  const options = { tenant: 'fcuster', database };
  const backup = async (row: RuntimeEnvelope) => { events.push('backup'); assert.deepEqual(row, envelope); return '/private/encrypted-backup.json'; };
  return { key, payload, store, options, events, backup, envelope: () => envelope, setEnvelope: (row: RuntimeEnvelope | null) => { envelope = row; }, register: () => { registered = true; } };
}

test('CLI defaults to dry-run and requires a reviewed digest for explicit apply', () => {
  assert.equal(parseRepairArguments(['--tenant', 'fcuster']).apply, false);
  assert.equal(parseRepairArguments(['--help']).help, true);
  for (const args of [[], ['--tenant', '_shared'], ['--tenant', 'fcuster', '--apply'], ['--tenant', 'fcuster', '--unknown'], ['--tenant', 'fcuster', '--tenant', 'other']]) assert.throws(() => parseRepairArguments(args));
  const args = parseRepairArguments(['--tenant', 'fcuster', '--apply', '--expect-digest', 'a'.repeat(64)]);
  assert.equal(args.apply, true);
});

test('dry-run previews exact scoped removals without backups, transactions or writes', async () => {
  const f = fixture(), before = structuredClone(f.envelope());
  const result = await repairOrphanRuntime(f.store, f.key, f.options, f.backup);
  assert.equal(result.applied, false);
  assert.equal(result.total, 4);
  assert.match(result.sourceDigest, /^[a-f0-9]{64}$/);
  assert.deepEqual(f.envelope(), before);
  assert.deepEqual(f.events, []);
  assert.ok(!JSON.stringify(result).includes('shared-value'));
});

test('apply backs up ciphertext before updating and preserves other scopes and shared values', async () => {
  const f = fixture();
  const preview = await repairOrphanRuntime(f.store, f.key, f.options, f.backup);
  const result = await repairOrphanRuntime(f.store, f.key, { ...f.options, apply: true, expectedDigest: preview.sourceDigest }, f.backup);
  assert.equal(result.applied, true);
  assert.deepEqual(f.events, ['backup', 'transaction', 'write']);
  const next = decodeRuntimeEnvelope(f.envelope(), f.key, database) as any;
  assert.deepEqual(next.tenants, [{ id: 'fcrww', secret: 'keep' }]);
  assert.deepEqual(next.pendingMongoBindings, [{ tenantId: 'other' }]);
  assert.deepEqual(next.explorer.clubRuntimes, [{ tenantId: 'fcuster', environment: 'test' }]);
  assert.deepEqual(next.explorer.setupRuntimes, f.payload.explorer.setupRuntimes);
  assert.deepEqual(next.explorer.keyBindings.bindings, [{ tenantId: 'fcrww', environment: 'development' }]);
  assert.deepEqual(next.shared, f.payload.shared);
});

test('any tenant definition, including a tombstone, blocks this orphan-only repair', async () => {
  const f = fixture(); f.register();
  await assert.rejects(repairOrphanRuntime(f.store, f.key, f.options, f.backup), /TenantDefinitionExists/);
  assert.deepEqual(f.events, []);
});

test('a changed reviewed digest blocks apply before backup or writes', async () => {
  const f = fixture();
  await assert.rejects(repairOrphanRuntime(f.store, f.key, { ...f.options, apply: true, expectedDigest: '0'.repeat(64) }, f.backup), /ConfigurationChanged/);
  assert.deepEqual(f.events, []);
});

test('backup failure prevents database mutation', async () => {
  const f = fixture(), preview = await repairOrphanRuntime(f.store, f.key, f.options, f.backup);
  await assert.rejects(repairOrphanRuntime(f.store, f.key, { ...f.options, apply: true, expectedDigest: preview.sourceDigest }, async () => { throw Error('BackupFailed'); }), /BackupFailed/);
  assert.deepEqual(f.events, []);
});

test('definition appearing during backup blocks apply inside transaction', async () => {
  const f = fixture(), preview = await repairOrphanRuntime(f.store, f.key, f.options, f.backup);
  await assert.rejects(repairOrphanRuntime(f.store, f.key, { ...f.options, apply: true, expectedDigest: preview.sourceDigest }, async () => { f.register(); return '/backup'; }), /TenantDefinitionExists/);
  assert.deepEqual(f.events, ['transaction']);
});

test('concurrent envelope changes and failed CAS refuse overwrites', async () => {
  for (const changeRead of [true, false]) {
    const f = fixture(), preview = await repairOrphanRuntime(f.store, f.key, f.options, f.backup);
    if (changeRead) f.store.transaction = async fn => { f.setEnvelope(encodeRuntimeEnvelope(f.payload, f.key, database)); await fn(f.store); };
    else f.store.compareAndSwap = async () => false;
    await assert.rejects(repairOrphanRuntime(f.store, f.key, { ...f.options, apply: true, expectedDigest: preview.sourceDigest }, f.backup), /ConfigurationChanged/);
  }
});

test('missing or malformed configuration and a wrong root key fail without effects', async () => {
  for (const mode of ['missing', 'malformed', 'wrong-key']) {
    const f = fixture();
    if (mode === 'missing') f.setEnvelope(null);
    if (mode === 'malformed') f.setEnvelope(encodeRuntimeEnvelope({ ...f.payload, tenants: {} }, f.key, database));
    await assert.rejects(repairOrphanRuntime(f.store, mode === 'wrong-key' ? randomBytes(32) : f.key, f.options, f.backup));
    assert.deepEqual(f.events, []);
  }
});

test('repeating a completed repair makes no backup or write', async () => {
  const f = fixture(), preview = await repairOrphanRuntime(f.store, f.key, f.options, f.backup);
  await repairOrphanRuntime(f.store, f.key, { ...f.options, apply: true, expectedDigest: preview.sourceDigest }, f.backup);
  f.events.length = 0;
  const next = await repairOrphanRuntime(f.store, f.key, { ...f.options, apply: true, expectedDigest: 'a'.repeat(64) }, f.backup);
  assert.equal(next.total, 0); assert.equal(next.applied, false); assert.deepEqual(f.events, []);
});

test('backup stores only the original encrypted envelope with private file permissions', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'runtime-repair-'));
  try {
    const f = fixture(), path = await writeEncryptedBackup(join(directory, 'backups'), f.envelope()!);
    const text = await readFile(path, 'utf8');
    assert.deepEqual(JSON.parse(text), f.envelope());
    assert.ok(!text.includes('shared-value'));
    assert.equal((await stat(path)).mode & 0o777, 0o600);
    assert.equal((await stat(join(directory, 'backups'))).mode & 0o777, 0o700);
    const unsafe = join(directory, 'unsafe'); await mkdir(unsafe); await chmod(unsafe, 0o755);
    await assert.rejects(writeEncryptedBackup(unsafe, f.envelope()!), /UnsafeBackupDirectory/);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('CLI help works without configuration or network access', () => {
  const output = execFileSync(process.execPath, ['--import', 'tsx', 'src/maintenance/repair-orphan-runtime-cli.ts', '--help'], { env: { PATH: process.env.PATH }, encoding: 'utf8' });
  assert.match(output, /Dry-run is the default/);
  assert.match(output, /--expect-digest/);
});

test('malformed vault credential JSON is diagnosed before network access without echoing it', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'runtime-repair-env-'));
  try {
    const path = join(directory, '.env');
    await writeFile(path, 'NODE_ENV=development\nSECRETS_KEYS_STRATEGY=LOCAL_KEYVAULT\nEXPLORER_CONTROL_DATABASE=test-control\nLOCAL_KEYVAULT_AUTH_JSON={super-secret-token\n');
    const result = spawnSync(process.execPath, ['--import', 'tsx', 'src/maintenance/repair-orphan-runtime-cli.ts', '--tenant', 'fcuster', '--env-file', path], { env: { PATH: process.env.PATH }, encoding: 'utf8' });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /LocalVaultAuthInvalid/);
    assert.ok(!result.stderr.includes('super-secret-token'));
  } finally { await rm(directory, { recursive: true, force: true }); }
});
