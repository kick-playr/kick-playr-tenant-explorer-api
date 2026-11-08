import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ClubRuntime } from '../src/club-runtime.js';
const tenant = {
  id: 'winikon',
  environment: 'development',
  hostname: 'winikon.localhost:4311',
} as any;
const session = {
  issuer: 'https://club.clerk.accounts.dev',
  subject: 'admin',
  token: 'signed-token',
};
const key = '11111111-1111-4111-8111-111111111111';
test('club team bridge forwards only exact creation, recovery, readiness and season commands', async () => {
  const calls: string[] = [];
  const runtime = new ClubRuntime(
    [
      {
        tenantId: 'winikon',
        environment: 'development',
        hostname: tenant.hostname,
        origin: 'http://127.0.0.1:4311',
      },
    ],
    async (url, init) => {
      calls.push(`${init!.method} ${url}`);
      return Response.json({ ok: true });
    },
  );
  for (const [method, path] of [
    ['GET', '/api/settings/teams'],
    ['GET', '/api/settings/teams/readiness'],
    ['POST', '/api/settings/teams/create'],
    ['POST', `/api/settings/teams/operations/${key}/resume`],
    ['POST', '/api/settings/teams/123/refresh'],
    ['PUT', '/api/settings/catalog/categories/team-seasons'],
  ])
    await runtime.request(
      tenant,
      session,
      method!,
      path!,
      method === 'GET' ? undefined : { expectedHash: 'one' },
    );
  assert.equal(calls.length, 6);
  for (const [method, path] of [
    ['POST', '/api/settings/teams'],
    ['GET', '/api/settings/teams/create'],
    ['DELETE', '/api/settings/teams/123'],
    ['POST', '/api/settings/teams/123/remap'],
    ['POST', '/api/settings/teams/operations/not-a-uuid/resume'],
    ['POST', '/api/settings/teams/0/refresh'],
    ['PUT', '/api/settings/catalog/categories/teams'],
    ['GET', '/api/settings/teams?account=foreign'],
  ])
    await assert.rejects(runtime.request(tenant, session, method!, path!, {}));
  await assert.rejects(
    runtime.request(
      { ...tenant, id: 'foreign' },
      session,
      'GET',
      '/api/settings/teams',
    ),
  );
  assert.equal(calls.length, 6);
});
