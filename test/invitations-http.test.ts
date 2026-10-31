import test from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import { generateKeyPairSync } from 'node:crypto';
import { createApp } from '../src/app.js';
import { MemoryRepository } from './memory-repository.js';
import { CredentialVault } from '../src/vault.js';
test('setup routes reject missing authentication, unknown operations and unconfigured adapters safely', async () => {
  const key = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const app = await createApp({
    repository: new MemoryRepository(),
    vault: new CredentialVault(Buffer.alloc(32, 1)),
    auth: {
      issuer: 'https://platform.example',
      authorizedParties: ['https://platform.example'],
      adminSubjects: ['operator'],
      jwtKey: key.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    },
    logger: false,
  });
  await app.init();
  const http = request(app.getHttpServer());
  try {
    await http
      .get('/api/platform/tenants/development/club/invitations')
      .expect(401);
    await http
      .get('/api/club/tenants/development/club/invitations')
      .expect(401);
    await http
      .post('/api/invitations/development/club/accept')
      .send({ token: 'x'.repeat(43), complete: true })
      .expect(400);
    await http
      .post('/api/invitations/development/club/accept')
      .send({ token: 'x'.repeat(43) })
      .expect(401);
    await http
      .post('/api/invitations/development/club/activate')
      .send({ complete: true })
      .expect(404);
    const r = await http
      .post('/api/invitations/development/club/preview')
      .send({ token: 'x'.repeat(43) })
      .expect(503);
    assert.equal(r.body.message, 'An unexpected error occurred');
    assert.equal(r.headers['referrer-policy'], 'no-referrer');
  } finally {
    await app.close();
  }
});
