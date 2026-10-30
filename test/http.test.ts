import 'reflect-metadata';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import request from 'supertest';
import { createApp } from '../src/app.js';
import { MemoryRepository } from './memory-repository.js';
import { CredentialVault } from '../src/vault.js';

const keys = generateKeyPairSync('rsa', { modulusLength: 2048 });
const issuer = 'https://platform.clerk.accounts.dev';
const origin = 'http://localhost:3002';
function token(overrides: Record<string, unknown> = {}) {
  const now = Math.floor(Date.now() / 1000);
  const header = Buffer.from(
    JSON.stringify({ alg: 'RS256', typ: 'JWT', kid: 'test' }),
  ).toString('base64url');
  const payload = Buffer.from(
    JSON.stringify({
      iss: issuer,
      sub: 'user_operator',
      sid: 'sess_test',
      azp: origin,
      iat: now,
      nbf: now - 5,
      exp: now + 60,
      ...overrides,
    }),
  ).toString('base64url');
  const data = `${header}.${payload}`;
  return `${data}.${sign('RSA-SHA256', Buffer.from(data), keys.privateKey).toString('base64url')}`;
}
async function fixture() {
  const repository = new MemoryRepository();
  const app = await createApp({
    repository,
    vault: new CredentialVault(Buffer.alloc(32, 1)),
    auth: {
      issuer,
      authorizedParties: [origin],
      adminSubjects: ['user_operator'],
      jwtKey: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    },
    logger: false,
  });
  await app.init();
  return { app, repository, http: request(app.getHttpServer()) };
}

test('health is public but platform routes require a valid allowlisted Clerk session', async () => {
  const { app, http } = await fixture();
  try {
    await http.get('/healthcheck').expect(200);
    await http.get('/api/platform/tenants').expect(401);
    await http
      .get('/api/platform/tenants/development/winikon/keys')
      .expect(401);
    await http
      .get('/api/platform/tenants')
      .set('Authorization', 'Bearer invalid')
      .expect(401);
    await http
      .get('/api/platform/tenants')
      .set('Authorization', `Bearer ${token({ sub: 'user_member' })}`)
      .expect(403);
    for (const claims of [
      { iss: 'https://foreign.clerk.accounts.dev' },
      { azp: 'https://foreign.ch' },
      { exp: 1 },
      { sid: '' },
    ]) {
      await http
        .get('/api/platform/tenants')
        .set('Authorization', `Bearer ${token(claims)}`)
        .expect(401);
    }
    const result = await http
      .get('/api/platform/tenants')
      .set('Authorization', `Bearer ${token()}`)
      .expect(200);
    assert.equal(result.body.total, 0);
    assert.match(result.headers['cache-control'] ?? '', /no-store/);
  } finally {
    await app.close();
  }
});

test('HTTP management validates writes and returns a conflict for stale saves', async () => {
  const { app, http } = await fixture();
  const auth = `Bearer ${token()}`;
  const tenant = {
    id: 'winikon',
    environment: 'development',
    hostname: 'winikon.localhost:4311',
    aliases: [],
    public: { name: 'FC Winikon', locale: 'de-CH' },
    secretReferences: { mongoUri: 'local:mongo', key: 'local:key' },
    identityRealm: issuer,
  };
  try {
    await http
      .post('/api/platform/tenants')
      .set('Authorization', auth)
      .send({ ...tenant, injected: 'no' })
      .expect(400);
    await http
      .post('/api/platform/tenants')
      .set('Authorization', auth)
      .set('Content-Type', 'application/json')
      .send('{')
      .expect(400);
    await http
      .put('/api/platform/tenants/development/winikon/credentials/mail')
      .set('Authorization', auth)
      .set('Content-Type', 'application/json')
      .send('{"value":"never-expose-invalid-secret" garbage}')
      .expect(400)
      .then((response) =>
        assert.ok(!response.text.includes('never-expose-invalid-secret')),
      );
    await http
      .post('/api/platform/tenants')
      .set('Authorization', auth)
      .send(tenant)
      .expect(201);
    const keys = await http
      .get('/api/platform/tenants/development/winikon/keys')
      .set('Authorization', auth)
      .expect(200);
    assert.equal(keys.body.status, 'unbound');
    assert.deepEqual(keys.body.files, []);
    await http
      .get('/api/platform/tenants/production/winikon/keys')
      .set('Authorization', auth)
      .expect(404);
    const path = '/api/platform/tenants/development/winikon';
    await http
      .patch(path)
      .set('Authorization', auth)
      .send({ expectedRevision: 1, status: 'active' })
      .expect(200);
    await http
      .patch(path)
      .set('Authorization', auth)
      .send({ expectedRevision: 1, status: 'disabled' })
      .expect(409);
    await http
      .get('/api/platform/tenants/production/winikon')
      .set('Authorization', auth)
      .expect(404);
    await http
      .put(`${path}/credentials/mail`)
      .set('Authorization', auth)
      .send({ expectedRevision: 2, label: 'Mail', value: 'never-expose-this' })
      .expect(200)
      .then((response) =>
        assert.ok(!response.text.includes('never-expose-this')),
      );
    const audit = await http
      .get(`${path}/audit`)
      .set('Authorization', auth)
      .expect(200);
    assert.equal(audit.body[0].actor, 'user_operator');
    assert.ok(!audit.text.includes('never-expose-this'));
  } finally {
    await app.close();
  }
});

test('unexpected storage errors are sanitized without leaking provider data', async () => {
  const { app, repository, http } = await fixture();
  repository.list = async () => {
    throw new Error('mongodb://private-connection?password=secret');
  };
  try {
    const response = await http
      .get('/api/platform/tenants')
      .set('Authorization', `Bearer ${token()}`)
      .expect(500);
    assert.equal(response.body.message, 'An unexpected error occurred');
    assert.ok(!response.text.includes('private-connection'));
  } finally {
    await app.close();
  }
});
