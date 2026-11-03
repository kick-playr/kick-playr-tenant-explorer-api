import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import request from 'supertest';
import {
  createApplicationRuntime,
  bindingDigest,
  type SecretsRuntime,
} from '@kick-playr/local-key-vault/runtime-client';
import { createLiveExplorer } from '../src/live-explorer.js';
import { createApp } from '../src/app.js';
import { CredentialVault } from '../src/vault.js';
import { MemoryRepository } from './memory-repository.js';
const scope = { environment: 'development', tenant: '_shared' };
const attrs = {
  enabled: true,
  created: 1,
  updated: 1,
  recoveryLevel: 'Purgeable' as const,
};
const canonical = (x: unknown) =>
  JSON.stringify(x, (_k, v) =>
    v && typeof v === 'object' && !Array.isArray(v)
      ? Object.fromEntries(
          Object.entries(v).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
        )
      : v,
  );
async function fixture(
  cold = false,
  customInvitation = false,
  operationTimeoutMs = 30000,
) {
  let activated = cold,
    denied = false,
    outage = false,
    generation = 1,
    legacyReads = 0;
  const disposed: number[] = [],
    composed: number[] = [];
  const original: Record<string, string> = {
    EXPLORER_MONGODB_URI: 'mongodb://old:credential@127.0.0.1/control',
    WORKFLOW_SHARED_WRAPPING_KEY_V1: Buffer.alloc(32, 1).toString('base64'),
    EXPLORER_CREDENTIAL_KEY: Buffer.alloc(32, 2).toString('hex'),
    MANAGER_SETUP_CONTROL_KEY: Buffer.alloc(32, 3).toString('base64'),
    CLERK_SECRET_KEY: 'sk_test_old',
    EXPLORER_INVITATION_SMTP_URL: 'smtps://old:credential@localhost',
  };
  const values = { ...original };
  const versions = Object.fromEntries(
    Object.keys(values).map((name, index) => [
      name,
      String(index + 1).repeat(32),
    ]),
  );
  const legacyBody = {
    schemaVersion: 1 as const,
    bindingRevision: 1,
    keySets: [],
    secrets: Object.keys(values).map((mapping) => ({
      mapping,
      purpose: mapping.toLowerCase().replaceAll('_', '-'),
      version: versions[mapping]!,
    })),
  };
  const legacyRequest = {
    ...legacyBody,
    bindingDigest: bindingDigest(legacyBody),
  };
  const legacySnapshot = {
    ...legacyRequest,
    ...scope,
    generation: 1,
    loadedAt: Date.now(),
    secrets: legacyBody.secrets.map((s) => ({
      ...s,
      value: original[s.mapping]!,
      attributes: { ...attrs },
    })),
  };
  const descriptor = () => {
    const resources = legacyBody.secrets
      .map((s) => ({
        kind: 'secrets',
        name:
          'kv-' +
          createHash('sha256')
            .update(
              JSON.stringify(['development', '_shared', 'secret', s.purpose]),
            )
            .digest('hex'),
        mapping: s.mapping,
        policy: 'latest',
        version: versions[s.mapping],
        classification:
          /(?:WRAPPING_KEY_V\d+|CONTROL_KEY|CREDENTIAL_KEY)$/.test(s.mapping)
            ? 'encryption-key'
            : 'secret',
        attributes: attrs,
      }))
      .sort((a, b) => (a.mapping < b.mapping ? -1 : 1));
    const identity = {
      schemaVersion: 2,
      application: 'explorer-api',
      scope,
      resources,
    };
    return {
      ...identity,
      generation,
      digest: createHash('sha256').update(canonical(identity)).digest('hex'),
    };
  };
  const fetcher: typeof fetch = async (input) => {
    if (denied || outage)
      return Response.json(
        { error: { code: 'private' } },
        { status: denied ? 403 : 503 },
      );
    const action = new URL(String(input)).pathname.split('/').at(-1);
    if (action === 'mode')
      return Response.json({
        schemaVersion: 2,
        application: 'explorer-api',
        scope,
        mode: activated ? 'live' : 'legacy',
      });
    if (action === 'desired') return Response.json(descriptor());
    if (action === 'snapshot') {
      const d = descriptor();
      return Response.json({
        ...d,
        resources: d.resources.map((r) => ({ ...r, value: values[r.mapping] })),
      });
    }
    if (action === 'in-use') return Response.json({ valid: true });
    if (action === 'register')
      return Response.json({
        instanceId: 'a'.repeat(36),
        proof: 'p'.repeat(43),
        expiresAt: Date.now() + 30000,
      });
    if (action === 'acknowledge')
      return Response.json({ accepted: true, expiresAt: Date.now() + 30000 });
    throw Error('Unexpected request');
  };
  const environment = {
    NODE_ENV: 'development',
    SECRETS_KEYS_STRATEGY: 'LOCAL_KEYVAULT',
    LOCAL_KEYVAULT_AUTH_JSON: JSON.stringify({
      schemaVersion: 1,
      grants: [{ ...scope, token: 'x'.repeat(32) }],
    }),
    ...(customInvitation
      ? {
          EXPLORER_INVITATION_BINDINGS_JSON:
            '[{"secretKeyEnv":"CUSTOM_CLERK_KEY"}]',
        }
      : {}),
  };
  const source = createLiveExplorer(environment, {
    operationTimeoutMs,
    legacyFactory: () =>
      ({
        loadApplication: async () => ({ scope, request: legacyRequest }),
        loadProcess: async () => {
          legacyReads++;
          if (cold) throw Error('obsolete values unavailable');
          return {
            strategy: 'LOCAL_KEYVAULT',
            mappings: {
              ...original,
              ...(customInvitation
                ? { CUSTOM_CLERK_KEY: 'sk_test_custom' }
                : {}),
            },
            snapshot: legacySnapshot,
          };
        },
        close() {},
      }) as unknown as SecretsRuntime,
    runtimeFactory: (config) =>
      createApplicationRuntime({ ...config, fetch: fetcher }),
    compose: async (secrets) => {
      const index = composed.length + 1;
      composed.push(index);
      // Real initialized Nest app, with a per-generation simulated pool and auth
      // credentials captured exactly where production composition captures them.
      const pool = { uri: secrets.environment.EXPLORER_MONGODB_URI };
      const app = await createApp({
        repository: new MemoryRepository(),
        vault: new CredentialVault(Buffer.alloc(32, 1)),
        auth: {
          issuer: 'https://example.clerk.accounts.dev',
          authorizedParties: ['http://localhost:3002'],
          adminSubjects: ['test'],
          secretKey: secrets.environment.CLERK_SECRET_KEY,
        },
        logger: false,
      });
      app.use('/slow', () => {});
      app.use('/captured', (_req: unknown, res: any) =>
        res.json({
          uri: pool.uri,
          clerk: secrets.environment.CLERK_SECRET_KEY,
          smtp: secrets.environment.EXPLORER_INVITATION_SMTP_URL,
          generation: index,
        }),
      );
      await app.init();
      return {
        handler: app.getHttpAdapter().getInstance(),
        close: async () => {
          disposed.push(index);
          secrets.close();
          await app.close();
        },
      };
    },
  });
  const update = (mapping: string, value: string) => {
    values[mapping] = value;
    versions[mapping] = 'f'.repeat(32);
    generation++;
  };
  return {
    source,
    disposed,
    composed,
    original,
    legacyReads: () => legacyReads,
    activate: () => {
      activated = true;
    },
    update,
    deny: () => {
      denied = true;
    },
    outage: () => {
      outage = true;
    },
    expireLegacy: () => {
      for (const secret of legacySnapshot.secrets)
        Object.assign(secret.attributes, {
          exp: Math.floor(Date.now() / 1000) - 1,
        });
    },
  };
}

test('explicit activation then polling replaces actual initialized Nest handlers and captured clients within five seconds', async () => {
  const f = await fixture();
  try {
    await f.source.initialize();
    const http = request(f.source.handler);
    assert.equal(
      (await http.get('/captured').expect(200)).body.clerk,
      'sk_test_old',
    );
    assert.equal(f.legacyReads(), 1);
    f.activate();
    await f.source.refresh();
    const before = f.composed.length;
    f.update('CLERK_SECRET_KEY', 'sk_test_new');
    f.update(
      'EXPLORER_MONGODB_URI',
      'mongodb://new:credential@127.0.0.1/control',
    );
    f.update(
      'EXPLORER_INVITATION_SMTP_URL',
      'smtps://new:credential@localhost',
    );
    const started = performance.now();
    while (f.composed.length <= before && performance.now() - started < 4500)
      await new Promise((resolve) => setTimeout(resolve, 50));
    const adopted = await http.get('/captured').expect(200);
    assert.equal(adopted.body.clerk, 'sk_test_new');
    assert.equal(
      adopted.body.uri,
      'mongodb://new:credential@127.0.0.1/control',
    );
    assert.equal(adopted.body.smtp, 'smtps://new:credential@localhost');
    assert.ok(performance.now() - started < 5000);
    assert.deepEqual(f.disposed, f.composed.slice(0, -1));
  } finally {
    await f.source.close();
  }
  assert.deepEqual(f.disposed, f.composed);
});

test('already-live cold startup loads immutable legacy metadata without obsolete process values', async () => {
  const f = await fixture(true);
  try {
    f.update('CLERK_SECRET_KEY', 'sk_test_current');
    await f.source.initialize();
    assert.equal(f.legacyReads(), 0);
    assert.equal(
      (await request(f.source.handler).get('/captured').expect(200)).body.clerk,
      'sk_test_current',
    );
  } finally {
    await f.source.close();
  }
});

test('encryption rotations stay pending without migration adapter, ordinary outage keeps valid current clients, and observed denial fences requests', async () => {
  const f = await fixture();
  try {
    await f.source.initialize();
    f.activate();
    await f.source.refresh();
    const before = f.composed.length;
    f.update('EXPLORER_CREDENTIAL_KEY', Buffer.alloc(32, 9).toString('hex'));
    await f.source.refresh();
    assert.equal(f.source.status().reason, 'MigrationRequired');
    assert.equal(f.composed.length, before);
    await request(f.source.handler).get('/captured').expect(200);
    f.outage();
    await f.source.refresh();
    await request(f.source.handler).get('/captured').expect(200);
    f.deny();
    await f.source.refresh().catch(() => {});
    await request(f.source.handler).get('/captured').expect(503);
  } finally {
    await f.source.close();
  }
});

test('custom invitation names are preserved in legacy and explicitly block unsupported live activation', async () => {
  const f = await fixture(false, true);
  try {
    await f.source.initialize();
    await request(f.source.handler).get('/captured').expect(200);
    f.activate();
    await assert.rejects(f.source.refresh());
    await request(f.source.handler).get('/captured').expect(503);
  } finally {
    await f.source.close();
  }
});

test('legacy discovery outage retains valid clients but observed denial and known expiry fence HTTP', async () => {
  const f = await fixture();
  try {
    await f.source.initialize();
    f.outage();
    await f.source.refresh();
    assert.equal(f.source.status().state, 'warning');
    await request(f.source.handler).get('/captured').expect(200);
    f.expireLegacy();
    await request(f.source.handler).get('/captured').expect(503);
  } finally {
    await f.source.close();
  }
  const denied = await fixture();
  try {
    await denied.source.initialize();
    denied.deny();
    await assert.rejects(denied.source.refresh());
    await request(denied.source.handler).get('/captured').expect(503);
  } finally {
    await denied.source.close();
  }
});

test('bounded response deadline ends an unfinished request and shutdown drains its captured pool', async () => {
  const f = await fixture(false, false, 30);
  try {
    await f.source.initialize();
    await assert.rejects(request(f.source.handler).get('/slow'));
  } finally {
    await f.source.close();
  }
  assert.deepEqual(f.disposed, [1]);
});
