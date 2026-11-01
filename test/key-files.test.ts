import { test } from 'node:test';
import assert from 'node:assert/strict';
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

test('legacy configuration file and environment JSON loading always fail closed', async () => {
  const before = process.env.EXPLORER_KEY_BINDINGS_JSON;
  process.env.EXPLORER_KEY_BINDINGS_JSON = JSON.stringify({
    version: 1,
    bindings: [],
  });
  try {
    await assert.rejects(
      KeyFileRegistry.load(),
      /encrypted database configuration/,
    );
  } finally {
    if (before === undefined) delete process.env.EXPLORER_KEY_BINDINGS_JSON;
    else process.env.EXPLORER_KEY_BINDINGS_JSON = before;
  }
});
test('database bindings reject file paths and public key variables', () => {
  const binding = {
    tenantId: 'club',
    environment: 'development',
    controlDatabase: 'control',
    keyReference: 'club:key',
    version: 'v1',
    profile: 'local',
  };
  assert.throws(
    () =>
      new KeyFileRegistry(
        [
          {
            ...binding,
            files: {
              wrapping: '/secret',
              index: '/secret',
              control: '/secret',
            },
          },
        ],
        'control',
      ),
  );
  assert.throws(
    () =>
      new KeyFileRegistry(
        [
          {
            ...binding,
            variables: {
              wrapping: 'NEXT_PUBLIC_WRAPPING_KEY_V1',
              index: 'CLUB_INDEX_KEY',
              control: 'CLUB_CONTROL_KEY',
            },
          },
        ],
        'control',
      ),
  );
  const configured = {
    ...binding,
    variables: {
      wrapping: 'CLUB_WRAPPING_KEY_V1',
      index: 'CLUB_INDEX_KEY',
      control: 'CLUB_CONTROL_KEY',
    },
  };
  assert.throws(
    () => new KeyFileRegistry([configured, configured], 'control'),
    /Duplicate/,
  );
});

test('derives DEMO key metadata from the encrypted runtime manifest without duplicate explorer registration', async () => {
  const { runtimeKeyBindings } = await import('../src/key-files.js');
  const row = {
    id: 'demo',
    wrappingKeyRef: 'env:WORKFLOW_REAL_DEMO_WRAPPING_KEY_V1',
    indexKeyRef: 'env:WORKFLOW_REAL_DEMO_INDEX_KEY',
    controlKeyRef: 'env:WORKFLOW_REAL_DEMO_CONTROL_KEY',
  };
  const bindings = runtimeKeyBindings(
    { profile: 'workflow-real', tenants: [row] },
    'control',
    [],
  );
  const env = Object.fromEntries(
    ['WRAPPING_KEY_V1', 'INDEX_KEY', 'CONTROL_KEY'].map((suffix, i) => [
      `WORKFLOW_REAL_DEMO_${suffix}`,
      Buffer.alloc(32, i + 1).toString('base64'),
    ]),
  );
  const registry = new KeyFileRegistry(bindings, 'control', env);
  const result = await registry.describe({
    id: 'demo',
    environment: 'development',
    secretReferences: { key: 'workflow-local:demo:key' },
  });
  assert.equal(result.status, 'connected');
  assert.equal(result.files.length, 3);
  assert.ok(
    !JSON.stringify(bindings).includes(env.WORKFLOW_REAL_DEMO_INDEX_KEY!),
  );
  assert.equal(
    (
      await registry.describe({
        id: 'other',
        environment: 'development',
        secretReferences: { key: 'workflow-local:demo:key' },
      })
    ).status,
    'unbound',
  );
  const stale = structuredClone(bindings) as any[];
  stale[0].version = 'v2';
  stale[0].profile = 'workflow-local';
  const refreshed = runtimeKeyBindings(
    { profile: 'workflow-real', tenants: [row] },
    'control',
    stale,
  ) as any[];
  assert.equal(refreshed[0].version, 'v1');
  assert.equal(refreshed[0].profile, 'workflow-real');
  const changed = structuredClone(bindings) as any[];
  changed[0].variables.index = 'OTHER_INDEX_KEY';
  assert.throws(() =>
    runtimeKeyBindings(
      { profile: 'workflow-real', tenants: [row] },
      'control',
      changed,
    ),
  );
  assert.throws(() =>
    runtimeKeyBindings(
      { profile: 'workflow-real', tenants: [row, row] },
      'control',
      [],
    ),
  );
  assert.throws(() =>
    runtimeKeyBindings(
      {
        profile: 'workflow-real',
        tenants: [{ ...row, indexKeyRef: 'env:NEXT_PUBLIC_INDEX_KEY' }],
      },
      'control',
      [],
    ),
  );
});

test('vault status uses scoped immutable source and never environment fallback, including restart gating', async () => {
  const binding = {
    tenantId: 'club',
    environment: 'development',
    controlDatabase: 'control',
    keyReference: 'workflow-local:club:key',
    version: 'v1',
    profile: 'workflow-local',
    variables: {
      wrapping: 'CLUB_WRAPPING_KEY_V1',
      index: 'CLUB_INDEX_KEY',
      control: 'CLUB_CONTROL_KEY',
    },
  };
  const values = Object.fromEntries(
    Object.values(binding.variables).map((n, i) => [
      n,
      Buffer.alloc(32, i + 1).toString('base64'),
    ]),
  );
  const source = {
    strategy: 'LOCAL_KEYVAULT' as const,
    tenantEnvironment: (_: unknown, revision?: number) => {
      if (revision !== 2) throw Error('restart');
      return values;
    },
    describe: () => ({
      generation: 8,
      version: 'v1',
      versions: {
        wrapping: 'pinned-w',
        index: 'pinned-i',
        control: 'pinned-c',
      },
    }),
  };
  const registry = new KeyFileRegistry(
    [binding],
    'control',
    {},
    undefined,
    source,
  );
  const tenant = {
    id: 'club',
    environment: 'development',
    configRevision: 2,
    secretReferences: { key: binding.keyReference },
  };
  const good = await registry.describe(tenant);
  assert.equal(good.status, 'connected');
  assert.equal(good.strategy, 'LOCAL_KEYVAULT');
  assert.equal(good.files[0]?.source, 'vault');
  assert.equal(good.files[0]?.version, 'pinned-w');
  assert.ok(!JSON.stringify(good).includes(values.CLUB_INDEX_KEY!));
  const stale = await registry.describe({ ...tenant, configRevision: 3 });
  assert.equal(stale.status, 'unavailable');
  assert.equal(stale.requiresRestart, true);
});
