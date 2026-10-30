import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, chmod, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { KeyFileRegistry } from '../src/key-files.js';

test('environment bindings expose only variable names and the original key fingerprints', async () => {
  const env = {
    FCRWW_WRAPPING_KEY_V1: Buffer.alloc(32, 1).toString('base64'),
    FCRWW_INDEX_KEY: Buffer.alloc(32, 2).toString('base64'),
    FCRWW_CONTROL_KEY: Buffer.alloc(32, 3).toString('base64'),
  };
  const registry = new KeyFileRegistry(
    [
      {
        tenantId: 'fcrww',
        environment: 'development',
        controlDatabase: 'control',
        keyReference: 'real-development:fcrww:key',
        version: 'v1',
        profile: 'real-development',
        variables: {
          wrapping: 'FCRWW_WRAPPING_KEY_V1',
          index: 'FCRWW_INDEX_KEY',
          control: 'FCRWW_CONTROL_KEY',
        },
      },
    ],
    'control',
    env,
  );
  const tenant = {
    id: 'fcrww',
    environment: 'development',
    secretReferences: { key: 'real-development:fcrww:key' },
  };
  const result = await registry.describe(tenant);
  assert.equal(result.status, 'connected');
  assert.equal(result.files[0]?.source, 'environment');
  assert.equal(result.files[0]?.variable, 'FCRWW_WRAPPING_KEY_V1');
  assert.equal(result.files[0]?.path, undefined);
  assert.equal(
    result.files[0]?.fingerprint,
    createHash('sha256').update(Buffer.alloc(32, 1)).digest('hex'),
  );
  assert.ok(!JSON.stringify(result).includes(env.FCRWW_WRAPPING_KEY_V1));
  delete (env as Partial<typeof env>).FCRWW_INDEX_KEY;
  const missing = await registry.describe(tenant);
  assert.equal(missing.status, 'unavailable');
  assert.equal(missing.files[1]?.status, 'missing');
});

test('cloud bindings load from JSON config without requiring a local metadata file', async () => {
  const env = {
    EXPLORER_KEY_BINDINGS_JSON: JSON.stringify({
      version: 1,
      bindings: [
        {
          tenantId: 'club',
          environment: 'development',
          controlDatabase: 'control',
          keyReference: 'local:club:key',
          version: 'v1',
          profile: 'local',
          variables: {
            wrapping: 'CLUB_WRAPPING_KEY_V1',
            index: 'CLUB_INDEX_KEY',
            control: 'CLUB_CONTROL_KEY',
          },
        },
      ],
    }),
    CLUB_WRAPPING_KEY_V1: Buffer.alloc(32, 1).toString('base64'),
    CLUB_INDEX_KEY: Buffer.alloc(32, 2).toString('base64'),
    CLUB_CONTROL_KEY: Buffer.alloc(32, 3).toString('base64'),
  };
  const registry = await KeyFileRegistry.load(
    '/does/not/exist',
    'control',
    env,
  );
  assert.equal(
    (
      await registry.describe({
        id: 'club',
        environment: 'development',
        secretReferences: { key: 'local:club:key' },
      })
    ).status,
    'connected',
  );
  await assert.rejects(
    KeyFileRegistry.load(undefined, 'control', {
      EXPLORER_KEY_BINDINGS_JSON: 'invalid JSON',
    }),
    /bindings are unavailable/,
  );
});

test('connects exact tenant/database/reference bindings without exposing key bytes', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'explorer-keys-'));
  try {
    const paths = {
      wrapping: join(dir, 'v1.key'),
      index: join(dir, 'index.key'),
      control: join(dir, 'control-v1.key'),
    };
    for (const [i, path] of Object.values(paths).entries())
      await writeFile(path, Buffer.alloc(32, i + 1), { mode: 0o600 });
    const registry = new KeyFileRegistry(
      [
        {
          tenantId: 'fcrww',
          environment: 'development',
          controlDatabase: 'app-local-control-kick-playr-ch',
          keyReference: 'real-development:fcrww:key',
          version: 'v1',
          profile: 'real-development',
          files: paths,
        },
      ],
      'app-local-control-kick-playr-ch',
    );
    const result = await registry.describe({
      id: 'fcrww',
      environment: 'development',
      secretReferences: { key: 'real-development:fcrww:key' },
    });
    assert.equal(result.status, 'connected');
    assert.equal(result.files.length, 3);
    assert.equal(
      result.files[0]?.fingerprint,
      createHash('sha256').update(Buffer.alloc(32, 1)).digest('hex'),
    );
    assert.ok(
      !JSON.stringify(result).includes(Buffer.alloc(32, 1).toString('base64')),
    );
    assert.equal(
      (
        await registry.describe({
          id: 'fcuster',
          environment: 'development',
          secretReferences: { key: 'real-development:fcrww:key' },
        })
      ).status,
      'unbound',
    );
    assert.equal(
      (
        await registry.describe({
          id: 'fcrww',
          environment: 'production',
          secretReferences: { key: 'real-development:fcrww:key' },
        })
      ).status,
      'unbound',
    );
    assert.equal(
      (
        await registry.describe({
          id: 'fcrww',
          environment: 'development',
          secretReferences: { key: 'workflow-local:fcrww:key' },
        })
      ).status,
      'unbound',
    );
    const foreign = new KeyFileRegistry(
      [
        {
          tenantId: 'fcrww',
          environment: 'development',
          controlDatabase: 'different-control',
          keyReference: 'real-development:fcrww:key',
          version: 'v1',
          profile: 'real-development',
          files: paths,
        },
      ],
      'app-local-control-kick-playr-ch',
    );
    assert.equal(
      (
        await foreign.describe({
          id: 'fcrww',
          environment: 'development',
          secretReferences: { key: 'real-development:fcrww:key' },
        })
      ).status,
      'unbound',
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('reports invalid, missing and insecure files without reading unrelated paths', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'explorer-keys-'));
  try {
    const wrapping = join(dir, 'v1.key'),
      index = join(dir, 'index.key'),
      control = join(dir, 'control.key');
    await writeFile(wrapping, Buffer.alloc(31), { mode: 0o600 });
    await writeFile(index, Buffer.alloc(32), { mode: 0o600 });
    await chmod(index, 0o644);
    const registry = new KeyFileRegistry(
      [
        {
          tenantId: 'club',
          environment: 'development',
          controlDatabase: 'control',
          keyReference: 'local:club:key',
          version: 'v1',
          profile: 'local',
          files: { wrapping, index, control },
        },
      ],
      'control',
    );
    const tenant = {
      id: 'club',
      environment: 'development',
      secretReferences: { key: 'local:club:key' },
    };
    const result = await registry.describe(tenant);
    assert.equal(result.status, 'unavailable');
    assert.deepEqual(
      result.files.map((file) => file.status),
      ['invalid', 'insecure', 'missing'],
    );
    assert.ok(result.files.every((file) => !file.fingerprint));
    await symlink(index, control);
    assert.equal(
      (await registry.describe(tenant)).files[2]?.status,
      'insecure',
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
