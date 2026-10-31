import test from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import { generateKeyPairSync } from 'node:crypto';
import { createApp } from '../src/app.js';
import { MemoryRepository } from './memory-repository.js';
import { CredentialVault } from '../src/vault.js';
import { InvitationPlatformGuard } from '../src/invitations/controller.js';
import type { RuntimeMongoService } from '../src/runtime-mongo.js';
test('fixed MongoDB save route requires authentication and passes only path scope plus live actor to the adapter', async () => {
  const keys = generateKeyPairSync('rsa', { modulusLength: 2048 });
  let called = 0;
  const metadata = {
    configured: true,
    editable: true,
    available: true,
    source: 'pending',
    revision: 'b'.repeat(64),
    requiresReload: true,
  };
  const mongo = {
    save: async (scope: unknown, body: unknown, actor: unknown) => {
      called++;
      assert.deepEqual(scope, { environment: 'development', tenantId: 'demo' });
      assert.deepEqual(body, {
        uri: 'PRIVATE_URI',
        expectedRevision: 'a'.repeat(64),
      });
      assert.equal((actor as { subject: string }).subject, 'operator');
      return metadata;
    },
  } as unknown as RuntimeMongoService;
  const app = await createApp({
    repository: new MemoryRepository(),
    vault: new CredentialVault(Buffer.alloc(32, 1)),
    runtimeMongo: mongo,
    auth: {
      issuer: 'https://platform.example',
      authorizedParties: ['https://platform.example'],
      adminSubjects: ['operator'],
      jwtKey: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    },
    logger: false,
  });
  await app.init();
  try {
    const http = request(app.getHttpServer()),
      path = '/api/platform/tenants/development/demo/onboarding/mongo-url';
    await http
      .post(path)
      .send({ uri: 'PRIVATE_URI', expectedRevision: 'a'.repeat(64) })
      .expect(401);
    assert.equal(called, 0);
    // Adapter/controller contract only; production live Clerk guard is tested by
    // the unauthorized request above and the existing identity/session suites.
    app.get(InvitationPlatformGuard).canActivate = async (context) => {
      const req = context.switchToHttp().getRequest();
      req.platformSubject = 'operator';
      req.platformExpiresAt = Date.now() + 60000;
      return true;
    };
    const response = await http
      .post(path)
      .send({ uri: 'PRIVATE_URI', expectedRevision: 'a'.repeat(64) })
      .expect(201);
    assert.equal(called, 1);
    assert.deepEqual(response.body, metadata);
    assert.ok(!JSON.stringify(response.body).includes('PRIVATE_URI'));
    assert.match(response.headers['cache-control'] ?? '', /no-store/);
    await http
      .post(path + '/export')
      .send({})
      .expect(404);
  } finally {
    await app.close();
  }
});
