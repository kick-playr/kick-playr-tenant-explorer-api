import 'reflect-metadata';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import request from 'supertest';
import { createApp } from '../src/app.js';
import { MemoryRepository } from './memory-repository.js';
import { CredentialVault } from '../src/vault.js';
import { TenantService } from '../src/tenant.service.js';
import { ClubRuntime } from '../src/club-runtime.js';

const keys = generateKeyPairSync('rsa', { modulusLength: 2048 });
const issuer = 'https://club.clerk.accounts.dev',
  origin = 'http://localhost:3002';
function token(
  subject = 'user_club',
  iss = issuer,
  signingKey = keys.privateKey,
) {
  const now = Math.floor(Date.now() / 1000);
  const data = [
    { alg: 'RS256', typ: 'JWT', kid: 'test' },
    {
      iss,
      sub: subject,
      sid: 'sess_test',
      azp: origin,
      iat: now,
      nbf: now - 5,
      exp: now + 60,
    },
  ]
    .map((x) => Buffer.from(JSON.stringify(x)).toString('base64url'))
    .join('.');
  return (
    'Bearer ' +
    data +
    '.' +
    sign('RSA-SHA256', Buffer.from(data), signingKey).toString('base64url')
  );
}
test('club discovery and reads are tenant scoped; platform routes stay operator only', async () => {
  const repository = new MemoryRepository(),
    vault = new CredentialVault(Buffer.alloc(32, 1));
  const service = new TenantService(repository, vault);
  for (const id of ['winikon', 'uster']) {
    await service.create(
      {
        id,
        environment: 'development',
        hostname: `${id}.localhost:4311`,
        aliases: [],
        public: { name: id, locale: 'de-CH' },
        secretReferences: { mongoUri: 'private:mongo', key: 'private:key' },
        identityRealm: issuer,
      },
      'operator',
    );
    await service.update(
      'development',
      id,
      { expectedRevision: 1, status: 'active' },
      'operator',
    );
  }
  await service.putUser(
    'development',
    'winikon',
    'user_club',
    {
      expectedRevision: 2,
      issuer,
      subject: 'user_club',
      contactId: 23,
      status: 'active',
      permissions: ['club:settings:read', 'club:settings:write'],
    },
    'operator',
  );
  const forwarded: { path: string; body: string | undefined }[] = [];
  const clubRuntime = new ClubRuntime(
    [
      {
        tenantId: 'winikon',
        environment: 'development',
        hostname: 'winikon.localhost:4311',
        origin: 'http://127.0.0.1:4311',
      },
    ],
    async (url, init) => {
      forwarded.push({
        path: String(url),
        body: init?.body as string | undefined,
      });
      return Response.json({ hash: 'next', currentSaison: '26.2' });
    },
  );
  const app = await createApp({
    clubRuntime,
    repository,
    vault,
    auth: {
      issuer,
      authorizedParties: [origin],
      adminSubjects: ['user_operator'],
      jwtKey: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    },
    logger: false,
  });
  await app.init();
  const http = request(app.getHttpServer());
  try {
    await http.get('/api/club/tenants').expect(401);
    const list = await http
      .get('/api/club/tenants')
      .set('Authorization', token())
      .expect(200);
    assert.deepEqual(
      list.body.items.map((x: { id: string }) => x.id),
      ['winikon'],
    );
    assert.ok(!JSON.stringify(list.body).includes('private:'));
    await http
      .get('/api/platform/tenants')
      .set('Authorization', token())
      .expect(403);
    await http
      .patch('/api/platform/tenants/development/winikon')
      .set('Authorization', token())
      .send({ expectedRevision: 3, status: 'disabled' })
      .expect(403);
    await http
      .get('/api/club/tenants/development/uster/settings')
      .set('Authorization', token())
      .expect(403);
    await http
      .get('/api/club/tenants/production/winikon/settings')
      .set('Authorization', token())
      .expect(403);
    await http
      .get('/api/club/tenants')
      .set('Authorization', token('user_member'))
      .expect(403);
    await http
      .get('/api/club/tenants')
      .set(
        'Authorization',
        token('user_club', 'https://foreign.clerk.accounts.dev'),
      )
      .expect(401);
    const access = await http
      .get('/api/explorer/access')
      .set('Authorization', token())
      .expect(200);
    assert.equal(access.body.role, 'club-admin');
    await http
      .get('/api/club/tenants/development/winikon/settings')
      .set('Authorization', token())
      .expect(200);
    await http
      .patch('/api/club/tenants/development/winikon/settings')
      .set('Authorization', token())
      .send({ expectedHash: 'before', patch: { currentSaison: '26.2' } })
      .expect(200);
    assert.equal(forwarded.length, 2);
    assert.deepEqual(
      repository.rows.get('development/winikon')!.metadata.credentials,
      [],
    );
    assert.deepEqual(
      repository.rows.get('development/winikon')!.metadata.configuration,
      {},
    );
    assert.ok(
      repository.events.some((e) => e.action === 'club.settings.completed'),
    );
    const original = structuredClone(
      repository.rows.get('development/winikon')!,
    );
    for (const change of [
      () => {
        repository.rows.get('development/winikon')!.definition.status =
          'suspended';
      },
      () => {
        repository.rows.get('development/winikon')!.authority!.configRevision =
          999;
      },
      () => {
        repository.rows.get('development/winikon')!.authority!.status =
          'disabled';
      },
      () => {
        const row = repository.rows.get('development/winikon')!;
        row.authority!.users.push({ ...row.authority!.users[0]! });
      },
    ]) {
      change();
      await http
        .get('/api/club/tenants/development/winikon/settings')
        .set('Authorization', token())
        .expect(403);
      repository.rows.set('development/winikon', structuredClone(original));
    }
    assert.equal(forwarded.length, 2);
    repository.rows.get('development/winikon')!.authority!.users[0]!.status =
      'revoked';
    await http
      .get('/api/club/tenants/development/winikon/settings')
      .set('Authorization', token())
      .expect(403);
  } finally {
    await app.close();
  }
});

test('a separately configured club Clerk realm cannot gain platform rights through a colliding subject', async () => {
  const clubIssuer = 'https://separate.clerk.accounts.dev',
    clubKeys = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const repository = new MemoryRepository(),
    vault = new CredentialVault(Buffer.alloc(32, 1)),
    service = new TenantService(repository, vault);
  await service.create(
    {
      id: 'separate',
      environment: 'development',
      hostname: 'separate.localhost:4311',
      aliases: [],
      public: { name: 'Separate club', locale: 'de-CH' },
      secretReferences: { mongoUri: 'private:mongo', key: 'private:key' },
      identityRealm: clubIssuer,
    },
    'operator',
  );
  await service.update(
    'development',
    'separate',
    { expectedRevision: 1, status: 'active' },
    'operator',
  );
  await service.putUser(
    'development',
    'separate',
    'user_operator',
    {
      expectedRevision: 2,
      issuer: clubIssuer,
      subject: 'user_operator',
      contactId: 23,
      status: 'active',
      permissions: ['club:settings:read', 'club:settings:write'],
    },
    'operator',
  );
  const app = await createApp({
    repository,
    vault,
    logger: false,
    auth: {
      issuer,
      authorizedParties: [origin],
      adminSubjects: ['user_operator'],
      jwtKey: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
      clubRealms: [
        {
          issuer: clubIssuer,
          authorizedParties: [origin],
          jwtKey: clubKeys.publicKey
            .export({ type: 'spki', format: 'pem' })
            .toString(),
        },
      ],
    },
  });
  await app.init();
  const http = request(app.getHttpServer());
  try {
    const clubToken = token('user_operator', clubIssuer, clubKeys.privateKey);
    const access = await http
      .get('/api/explorer/access')
      .set('Authorization', clubToken)
      .expect(200);
    assert.equal(access.body.role, 'club-admin');
    await http
      .get('/api/platform/tenants')
      .set('Authorization', clubToken)
      .expect(401);
    await http
      .get('/api/club/tenants')
      .set('Authorization', token('user_operator', clubIssuer))
      .expect(401);
    await http
      .get('/api/club/tenants')
      .set(
        'Authorization',
        token(
          'user_operator',
          'https://unknown.clerk.accounts.dev',
          clubKeys.privateKey,
        ),
      )
      .expect(401);
  } finally {
    await app.close();
  }
});
