import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createExplorerSecrets } from '../src/secrets.js';

const value = (n: number) => Buffer.alloc(32, n).toString('base64');
const processValues = {
  EXPLORER_MONGODB_URI:
    'mongodb://user:pass@localhost/control?tls=true&authSource=admin',
  WORKFLOW_SHARED_WRAPPING_KEY_V1: value(1),
  EXPLORER_CREDENTIAL_KEY: Buffer.alloc(32, 2).toString('hex'),
  MANAGER_SETUP_CONTROL_KEY: value(3),
  CLERK_SECRET_KEY: 'sk_test_placeholder',
};
function runtime() {
  const calls: unknown[] = [];
  return {
    calls,
    loadProcess: async (app: string, policy: unknown) => {
      calls.push([app, policy]);
      return { strategy: 'LOCAL_KEYVAULT', mappings: processValues };
    },
    loadTenant: async (tenant: string, revision: number) => {
      calls.push([tenant, revision]);
      return {
        environment: 'development',
        tenant,
        bindingRevision: revision,
        bindingDigest: 'd'.repeat(64),
        generation: 8,
        loadedAt: Date.now(),
        keySets: [
          {
            reference: `workflow-local:${tenant}:key`,
            mappings: {
              wrapping: 'CLUB_WRAPPING_KEY_V1',
              index: 'CLUB_INDEX_KEY',
              control: 'CLUB_CONTROL_KEY',
            },
            currentWrappingVersion: 'v1',
            wrappingVersions: [
              {
                keyVersion: 'v1',
                vaultVersion: 'w',
                value: value(4),
                attributes: {},
              },
            ],
            index: { vaultVersion: 'i', value: value(5), attributes: {} },
            control: { vaultVersion: 'c', value: value(6), attributes: {} },
          },
        ],
        secrets: [],
      };
    },
    close() {},
  };
}
test('vault process secrets replace stale env, without changing process or retaining tenant env fallback', async () => {
  const transport = runtime();
  const input = {
    NODE_ENV: 'development',
    SECRETS_KEYS_STRATEGY: 'LOCAL_KEYVAULT',
    CLERK_SECRET_KEY: 'stale',
    CLUB_INDEX_KEY: 'stale-tenant',
  };
  const source = await createExplorerSecrets(input, transport as any);
  assert.equal(
    source.environment.CLERK_SECRET_KEY,
    processValues.CLERK_SECRET_KEY,
  );
  assert.equal(source.environment.CLUB_INDEX_KEY, undefined);
  assert.equal(input.CLERK_SECRET_KEY, 'stale');
  assert.equal(transport.calls.length, 1);
  assert.equal((transport.calls[0] as any)[0], 'explorer-api');
});
test('tenant snapshots are pinned at boot and a later revision requires restart, with no additional load', async () => {
  const transport = runtime(),
    source = await createExplorerSecrets(
      { NODE_ENV: 'development', SECRETS_KEYS_STRATEGY: 'LOCAL_KEYVAULT' },
      transport as any,
    );
  await source.initializeTenant({
    environment: 'development',
    tenantId: 'club',
    configRevision: 2,
  });
  const binding = {
    environment: 'development',
    tenantId: 'club',
    keyReference: 'workflow-local:club:key',
    variables: {
      wrapping: 'CLUB_WRAPPING_KEY_V1',
      index: 'CLUB_INDEX_KEY',
      control: 'CLUB_CONTROL_KEY',
    },
  };
  assert.equal(source.tenantEnvironment(binding, 2).CLUB_INDEX_KEY, value(5));
  assert.throws(() => source.tenantEnvironment(binding, 3), /restart/i);
  assert.throws(
    () => source.tenantEnvironment({ ...binding, tenantId: 'other' }, 2),
    /restart/i,
  );
  assert.equal(transport.calls.length, 2);
  assert.ok(!JSON.stringify(source.describe(binding, 2)).includes(value(5)));
});
test('missing required vault process values fail even when env supplies them', async () => {
  const transport = runtime();
  transport.loadProcess = async () =>
    ({ strategy: 'LOCAL_KEYVAULT', mappings: {} }) as any;
  await assert.rejects(
    createExplorerSecrets(
      {
        NODE_ENV: 'development',
        SECRETS_KEYS_STRATEGY: 'LOCAL_KEYVAULT',
        ...processValues,
      },
      transport as any,
    ),
    /unavailable/i,
  );
});

test('vault mode never reads legacy persisted deletion credentials', async () => {
  const { DeletionInventoryResolver } =
    await import('../src/deletion/inventory.js');
  const { CredentialVault } = await import('../src/vault.js');
  let databaseRead = false;
  const client = {
    db: () => {
      databaseRead = true;
      throw Error('legacy credential read');
    },
  };
  const inventory = new DeletionInventoryResolver(
    client as any,
    'control',
    Buffer.alloc(32),
    new CredentialVault(Buffer.alloc(32)),
    'LOCAL_KEYVAULT',
  );
  await assert.rejects(
    inventory.resolve({ environment: 'development', tenantId: 'club' }),
    /vault/i,
  );
  assert.equal(databaseRead, false);
});

test('a restarted vault source uses current v2 with retained v1 even when legacy binding metadata is v1', async () => {
  const transport = runtime();
  const load = transport.loadTenant;
  transport.loadTenant = async (tenant, revision) => {
    const snapshot = await load(tenant, revision);
    snapshot.keySets[0]!.currentWrappingVersion = 'v2';
    snapshot.keySets[0]!.wrappingVersions.push({
      keyVersion: 'v2',
      vaultVersion: 'w2',
      value: value(7),
      attributes: {},
    });
    return snapshot;
  };
  const source = await createExplorerSecrets(
    { NODE_ENV: 'development', SECRETS_KEYS_STRATEGY: 'LOCAL_KEYVAULT' },
    transport as any,
  );
  await source.initializeTenant({
    environment: 'development',
    tenantId: 'club',
    configRevision: 3,
  });
  const binding = {
    environment: 'development',
    tenantId: 'club',
    keyReference: 'workflow-local:club:key',
    version: 'v1',
    variables: {
      wrapping: 'CLUB_WRAPPING_KEY_V1',
      index: 'CLUB_INDEX_KEY',
      control: 'CLUB_CONTROL_KEY',
    },
  };
  assert.equal(source.describe(binding, 3).version, 'v2');
  assert.equal(
    source.tenantEnvironment(binding, 3).CLUB_WRAPPING_KEY_V1,
    value(7),
  );
  assert.throws(() => source.tenantEnvironment(binding, 4), /restart/i);
});
