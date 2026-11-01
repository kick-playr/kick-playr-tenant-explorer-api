import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createSecretsRuntime,
  bindingDigest,
  type RuntimeSnapshotRequest,
} from '@kick-playr/local-key-vault/runtime-client';
import { createExplorerSecrets } from '../src/secrets.js';

test('Explorer startup consumes the pinned published atomic snapshot contract without provisioning requests', async () => {
  const values: Record<string, string> = {
    EXPLORER_MONGODB_URI:
      'mongodb://user:placeholder@localhost/control?tls=true&authSource=admin',
    WORKFLOW_SHARED_WRAPPING_KEY_V1: Buffer.alloc(32, 1).toString('base64'),
    EXPLORER_CREDENTIAL_KEY: Buffer.alloc(32, 2).toString('hex'),
    MANAGER_SETUP_CONTROL_KEY: Buffer.alloc(32, 3).toString('base64'),
    CLERK_SECRET_KEY: 'sk_test_placeholder123',
  };
  const body = {
    schemaVersion: 1 as const,
    bindingRevision: 1,
    keySets: [],
    secrets: Object.keys(values).map((mapping, i) => ({
      mapping,
      purpose: `explorer-process-${i}`,
      version: String(i + 1).repeat(32),
    })),
  };
  const request: RuntimeSnapshotRequest = {
    ...body,
    bindingDigest: bindingDigest(body),
  };
  const env = {
    NODE_ENV: 'development',
    SECRETS_KEYS_STRATEGY: 'LOCAL_KEYVAULT',
    LOCAL_KEYVAULT_BINDINGS_JSON: JSON.stringify({
      schemaVersion: 1,
      applications: {
        'explorer-api': {
          scope: { environment: 'development', tenant: '_shared' },
          request,
        },
      },
      tenants: [],
    }),
    LOCAL_KEYVAULT_AUTH_JSON: JSON.stringify({
      schemaVersion: 1,
      grants: [
        {
          environment: 'development',
          tenant: '_shared',
          token: 'x'.repeat(32),
        },
      ],
    }),
  };
  let calls = 0;
  const runtime = createSecretsRuntime({
    environment: env,
    fetch: async (url, options) => {
      calls++;
      assert.equal(url, 'http://127.0.0.1:4000/local/runtime-snapshot');
      assert.equal(options?.method, 'POST');
      assert.equal(options?.redirect, 'error');
      return Response.json({
        schemaVersion: 1,
        environment: 'development',
        tenant: '_shared',
        bindingRevision: 1,
        bindingDigest: request.bindingDigest,
        generation: 2,
        loadedAt: Date.now(),
        keySets: [],
        secrets: request.secrets.map((item) => ({
          ...item,
          value: values[item.mapping],
          attributes: {
            enabled: true,
            created: 1,
            updated: 1,
            recoveryLevel: 'Purgeable',
          },
        })),
      });
    },
  });
  const source = await createExplorerSecrets(env, runtime);
  assert.equal(
    source.environment.WORKFLOW_SHARED_WRAPPING_KEY_V1,
    values.WORKFLOW_SHARED_WRAPPING_KEY_V1,
  );
  assert.equal(calls, 1);
  source.close();
});
