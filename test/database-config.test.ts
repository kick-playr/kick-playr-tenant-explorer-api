import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, randomBytes, generateKeyPairSync } from 'node:crypto';
import { loadExplorerConfiguration } from '../src/database-config.js';

const key = Buffer.alloc(32, 7),
  database = 'control';
const publicKey = generateKeyPairSync('rsa', { modulusLength: 2048 })
  .publicKey.export({ type: 'spki', format: 'pem' })
  .toString();
const explorer = () => ({
  issuer: 'https://platform.clerk.accounts.dev',
  authorizedParties: ['http://localhost:3002'],
  adminSubjects: ['user_operator'],
  keyBindings: { version: 1, bindings: [] },
  clubRuntimes: [
    {
      tenantId: 'club',
      environment: 'development',
      hostname: 'club.localhost:4311',
      origin: 'http://club.localhost:4311',
    },
  ],
  clubRealms: [
    {
      issuer: 'https://club.clerk.accounts.dev',
      authorizedParties: ['http://club.explorer.localhost:3002'],
      jwtKey: publicKey,
    },
  ],
  frontendHosts: {
    'club.explorer.localhost:3002': {
      publishableKey: 'pk_test_Y2x1YiQ=',
      secretVariable: 'EXPLORER_CLUB_CLUB_CLERK_SECRET_KEY',
    },
  },
  platformHosts: ['localhost:3002'],
});
function row(
  value: unknown = {
    version: 2,
    explorer: explorer(),
    privateOther: 'do-not-expose',
  },
) {
  const nonce = randomBytes(12),
    cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(
    Buffer.from(
      JSON.stringify(['kick-playr:tenant-workflow-configuration', database, 1]),
    ),
  );
  const ciphertext = Buffer.concat([
    cipher.update(JSON.stringify(value)),
    cipher.final(),
  ]);
  return {
    _id: 'runtime:development',
    version: 1,
    nonce: nonce.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
  };
}
function client(document: unknown) {
  return {
    db: (name: string) => {
      assert.equal(name, database);
      return {
        collection: (name: string) => {
          assert.equal(name, 'tenantWorkflowConfiguration');
          return {
            findOne: async (filter: unknown) => {
              assert.deepEqual(filter, { _id: 'runtime:development' });
              return document;
            },
          };
        },
      };
    },
  };
}
test('setup destination is separately pinned so first-owner setup does not depend on operational grants',async()=>{
  const setupRuntimes=[{environment:'development',tenantId:'club',origin:'http://localhost:3000'}];
  const result=await loadExplorerConfiguration(client(row({version:2,explorer:{...explorer(),setupRuntimes}})) as never,database,key);
  assert.deepEqual(result.setupRuntimes,setupRuntimes);
  await assert.rejects(loadExplorerConfiguration(client(row({version:2,explorer:{...explorer(),setupRuntimes:[{environment:'production',tenantId:'club',origin:'http://untrusted.example'}]}})) as never,database,key));
});
test('loads only validated Explorer DB projection and never falls back to environment JSON', async () => {
  const previous = process.env.EXPLORER_CLUB_RUNTIMES_JSON;
  process.env.EXPLORER_CLUB_RUNTIMES_JSON = 'invalid legacy config';
  try {
    const result = await loadExplorerConfiguration(
      client(row()) as any,
      database,
      key,
    );
    assert.equal(result.clubRuntimes.length, 1);
    assert.deepEqual(result.platformHosts, ['localhost:3002']);
    assert.ok(!JSON.stringify(result).includes('do-not-expose'));
    await assert.rejects(
      loadExplorerConfiguration(client(null) as any, database, key),
      /unavailable/,
    );
  } finally {
    if (previous === undefined) delete process.env.EXPLORER_CLUB_RUNTIMES_JSON;
    else process.env.EXPLORER_CLUB_RUNTIMES_JSON = previous;
  }
});
test('rejects authenticated-envelope tamper, wrong database/key and malformed settings', async () => {
  const tampered = row();
  tampered.tag = Buffer.alloc(16).toString('base64');
  await assert.rejects(
    loadExplorerConfiguration(client(tampered) as any, database, key),
    /unavailable/,
  );
  await assert.rejects(
    loadExplorerConfiguration(
      client(row()) as any,
      database,
      Buffer.alloc(32, 8),
    ),
    /unavailable/,
  );
  const boundRow = row();
  await assert.rejects(
    loadExplorerConfiguration(
      {
        db: () => ({ collection: () => ({ findOne: async () => boundRow }) }),
      } as any,
      'other-control',
      key,
    ),
    /unavailable/,
  );
  await assert.rejects(
    loadExplorerConfiguration(
      client(
        row({
          version: 2,
          explorer: { ...explorer(), platformHosts: ['bad/path'] },
        }),
      ) as any,
      database,
      key,
    ),
    /unavailable/,
  );
  await assert.rejects(
    loadExplorerConfiguration(
      client(row({ version: 2 })) as any,
      database,
      key,
    ),
    /unavailable/,
  );
});
