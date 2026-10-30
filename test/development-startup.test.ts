import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

test('development loader initializes Nest and enforces the configured rate limit', () => {
  const result = spawnSync(
    process.execPath,
    [
      '--import',
      'tsx',
      '--input-type=module',
      '-e',
      `
      import assert from 'node:assert/strict';
      import request from 'supertest';
      import { createApp } from './src/app.ts';
      import { MemoryRepository } from './test/memory-repository.ts';
      import { CredentialVault } from './src/vault.ts';
      const app = await createApp({
        repository: new MemoryRepository(),
        vault: new CredentialVault(Buffer.alloc(32, 1)),
        auth: {
          issuer: 'https://example.clerk.accounts.dev',
          authorizedParties: ['http://localhost:3002'],
          adminSubjects: ['user_test'],
          jwtKey: 'synthetic-key',
        },
        logger: false,
      });
      try {
        await app.init();
        const http = request(app.getHttpServer());
        for (let n = 0; n < 120; n++) await http.get('/healthcheck').expect(200);
        await http.get('/healthcheck').expect(429);
        assert.ok(true);
        console.log('development startup and rate limiting passed');
      } finally { await app.close(); }
    `,
    ],
    { cwd: process.cwd(), encoding: 'utf8', timeout: 15000 },
  );
  assert.equal(
    result.status,
    0,
    `Development startup failed: ${result.stderr || result.stdout}`,
  );
  assert.match(result.stdout, /development startup and rate limiting passed/);
});
