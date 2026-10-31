import 'reflect-metadata';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import { createApp } from '../src/app.js';
import { MemoryRepository } from './memory-repository.js';
import { CredentialVault } from '../src/vault.js';
import { PublicRealmDirectory } from '../src/public-realms.js';

test('public realm lookup exposes exact configured public projections and rejects unknown or ambiguous hosts', async () => {
  const app = await createApp({
    repository: new MemoryRepository(),
    vault: new CredentialVault(Buffer.alloc(32, 1)),
    logger: false,
    auth: {
      issuer: 'https://platform.clerk.accounts.dev',
      authorizedParties: ['http://localhost:3002'],
      adminSubjects: ['user_operator'],
      jwtKey: 'synthetic-key',
    },
    publicRealms: new PublicRealmDirectory({
      frontendHosts: {
        'club.explorer.localhost:3002': {
          publishableKey: 'pk_test_Y2x1YiQ=',
          secretVariable: 'EXPLORER_CLUB_CLUB_CLERK_SECRET_KEY',
          secretValue: 'MUST-NOT-LEAK',
        } as any,
      },
      platformHosts: ['localhost:3002'],
    }),
  });
  try {
    await app.init();
    const http = request(app.getHttpServer());
    const club = await http
      .get('/public/realm')
      .query({ host: 'club.explorer.localhost:3002' })
      .expect(200);
    assert.deepEqual(club.body, {
      host: 'club.explorer.localhost:3002',
      club: true,
      publishableKey: 'pk_test_Y2x1YiQ=',
      secretVariable: 'EXPLORER_CLUB_CLUB_CLERK_SECRET_KEY',
    });
    assert.ok(!JSON.stringify(club.body).includes('MUST-NOT-LEAK'));
    const platform = await http
      .get('/public/realm')
      .query({ host: 'localhost:3002' })
      .expect(200);
    assert.deepEqual(platform.body, { host: 'localhost:3002', club: false });
    await http
      .get('/public/realm')
      .query({ host: 'unknown.example' })
      .expect(404);
    for (const target of [
      '/public/realm',
      '/public/realm?host=localhost:3002&extra=true',
      '/public/realm?host=localhost:3002&host=evil.example',
      '/public/realm?host=localhost:3002/path',
      '/public/realm?host=localhost:99999',
      '/public/realm?host=LOCALHOST:3002',
    ])
      await http.get(target).expect(400);
  } finally {
    await app.close();
  }
});
