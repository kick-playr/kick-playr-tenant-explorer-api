import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ClubRuntime } from '../src/club-runtime.js';
import type { Definition } from '../src/contracts.js';
const tenant = {
  id: 'winikon',
  environment: 'development',
  hostname: 'winikon.localhost:4311',
} as Definition;
const session = {
  issuer: 'https://club.clerk.accounts.dev',
  subject: 'user_admin',
  token: 'signed-token',
};
const bindings = [
  {
    tenantId: 'winikon',
    environment: 'development',
    hostname: tenant.hostname,
    origin: 'http://127.0.0.1:4311',
  },
];
test('club bridge sends only the current user bearer to a fixed tenant proxy and preserves conflicts', async () => {
  const calls: { url: string; init: RequestInit }[] = [];
  const runtime = new ClubRuntime(bindings, async (url, init) => {
    calls.push({ url: String(url), init: init! });
    return Response.json({ hash: 'next', currentSaison: '26.1' });
  });
  await runtime.request(tenant, session, 'PATCH', '/api/settings', {
    expectedHash: 'before',
    patch: { currentSaison: '26.1' },
  });
  assert.equal(calls[0]!.url, 'http://127.0.0.1:4311/api/settings');
  const headers = calls[0]!.init.headers as Record<string, string>;
  assert.equal(headers.Host, tenant.hostname);
  assert.equal(headers.Authorization, 'Bearer signed-token');
  assert.equal(headers.Origin, 'http://winikon.localhost:4311');
  assert.equal(headers.Cookie, undefined);
  assert.equal(headers['x-kick-playr-role'], 'ADMIN');
  assert.equal(calls[0]!.init.redirect, 'error');
  await assert.rejects(
    runtime.request(
      { ...tenant, id: 'foreign' },
      session,
      'GET',
      '/api/settings',
    ),
  );
  for (const path of [
    '/api/admin/users',
    '/api/settings/../keys',
    '/api/settings/integrations/../../users',
  ])
    await assert.rejects(runtime.request(tenant, session, 'PUT', path, {}));
  assert.equal(calls.length, 1);
  const conflict = new ClubRuntime(bindings, async () =>
    Response.json({ message: 'sensitive-provider-value' }, { status: 409 }),
  );
  await assert.rejects(
    conflict.request(tenant, session, 'PATCH', '/api/settings', {}),
    (e) => {
      assert.ok(!String(e).includes('sensitive-provider-value'));
      return (e as { getStatus(): number }).getStatus() === 409;
    },
  );
});
test('runtime bindings reject duplicate tenants, credentials, paths and insecure production origins', () => {
  for (const bad of [
    [...bindings, ...bindings],
    [{ ...bindings[0], origin: 'http://user:secret@localhost:4311' }],
    [{ ...bindings[0], origin: 'http://localhost:4311/path' }],
    [{ ...bindings[0], environment: 'production' }],
  ])
    assert.throws(() => new ClubRuntime(bad));
});

test('native runtime transport preserves the configured virtual Host on a real HTTP connection', async () => {
  const { createServer } = await import('node:http');
  let received = '';
  const server = createServer((req, res) => {
    received = req.headers.host ?? '';
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ hash: 'one' }));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const port = (server.address() as { port: number }).port;
    const runtime = new ClubRuntime([
      { ...bindings[0], origin: `http://127.0.0.1:${port}` },
    ]);
    await runtime.request(tenant, session, 'GET', '/api/settings');
    assert.equal(received, tenant.hostname);
  } finally {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  }
});

test('runtime authentication rejection explains a missing session audience without exposing the token', async () => {
  const token =
    'header.' +
    Buffer.from(
      JSON.stringify({
        sub: 'user_admin',
        sid: 'session',
        azp: 'https://explorer.example',
      }),
    ).toString('base64url') +
    '.signature';
  const runtime = new ClubRuntime(bindings, async () =>
    Response.json({ message: 'provider-private-detail' }, { status: 401 }),
  );
  await assert.rejects(
    runtime.request(tenant, { ...session, token }, 'GET', '/api/settings'),
    (error) => {
      assert.match(String(error), /session token.*audience/i);
      assert.ok(!String(error).includes(token));
      assert.ok(!String(error).includes('provider-private-detail'));
      return true;
    },
  );
});

test('club settings responses support the runtime one MiB record budget and reject excess', async () => {
  const settings = { hash: 'one', clubText: 'x'.repeat(300_000) };
  const runtime = new ClubRuntime(bindings, async () =>
    Response.json(settings),
  );
  assert.deepEqual(
    await runtime.request(tenant, session, 'GET', '/api/settings'),
    settings,
  );
  const oversized = new ClubRuntime(bindings, async () =>
    Response.json({ clubText: 'x'.repeat(1024 * 1024) }),
  );
  await assert.rejects(
    oversized.request(tenant, session, 'GET', '/api/settings'),
  );
});

test('forwards only catalog reads and general label mappings, preserving revision bodies', async () => {
  const calls: { url: string; init: RequestInit }[] = [];
  const runtime = new ClubRuntime(bindings, async (url, init) => {
    calls.push({ url: String(url), init: init! });
    return Response.json({ id: 'catalog', hash: 'after', items: [] });
  });
  const body = { expectedHash: 'before', selectors: [{ id: 42 }] };
  await runtime.request(
    tenant,
    session,
    'GET',
    '/api/settings/catalog/categories',
  );
  await runtime.request(
    tenant,
    session,
    'PUT',
    '/api/settings/catalog/branches/flags/isTrial',
    body,
  );
  assert.deepEqual(JSON.parse(String(calls[1]!.init.body)), body);
  assert.equal(
    (calls[1]!.init.headers as Record<string, string>).Host,
    tenant.hostname,
  );
  for (const path of [
    '/api/settings/catalog/categories/teams',
    '/api/settings/catalog/categories/coaches1418',
    '/api/settings/catalog/branches/player-trainers',
    '/api/settings/catalog/categories/team-seasons',
    '/api/settings/catalog/categories/flags/isTeam',
    '/api/settings/catalog/branches/flags/unknown',
    '/api/settings/catalog/branches/flags/isKiosk',
    '/api/settings/catalog/categories/flags/isAdmin',
  ])
    await assert.rejects(runtime.request(tenant, session, 'PUT', path, body));
  assert.equal(calls.length, 2);
});

test('club catalog controller resolves the signed-in tenant and audits focused writes', async () => {
  const { ClubController } = await import('../src/club.controller.js');
  const calls: string[] = [];
  const runtime = new ClubRuntime(bindings, async (url) => {
    calls.push(String(url));
    return Response.json({ id: 'catalog', hash: 'after', items: [] });
  });
  const audits: string[] = [];
  const clubs = {
    require: async (e: string, id: string, current: unknown) => {
      assert.equal(e, 'development');
      assert.equal(id, tenant.id);
      assert.equal(current, session);
      return tenant;
    },
    audit: async (_tenant: unknown, _session: unknown, event: string) => {
      audits.push(event);
    },
  };
  const controller = new ClubController(clubs as never, runtime);
  const req = { query: {}, explorerSession: session } as never;
  await controller.catalog(req, 'development', tenant.id, 'categories');
  await controller.catalogFlag(
    req,
    'development',
    tenant.id,
    'branches',
    'isTrial',
    { expectedHash: 'before', selectors: [] },
  );
  assert.deepEqual(audits, ['club.settings.intent', 'club.settings.completed']);
  assert.equal(calls.length, 2);
  assert.throws(() =>
    controller.catalogFlag(
      req,
      'development',
      tenant.id,
      'categories',
      'isTeam',
      {},
    ),
  );
  clubs.require = async () => {
    throw Error('Forbidden');
  };
  await assert.rejects(
    controller.catalog(req, 'development', tenant.id, 'categories'),
  );
  assert.equal(calls.length, 2);
});

test('branding projection is a read-only tenant-bound operation', async () => {
  const calls: string[] = [];
  const runtime = new ClubRuntime(bindings, async (url) => {
    calls.push(String(url));
    return Response.json({ branding: null });
  });
  assert.deepEqual(
    await runtime.request(tenant, session, 'GET', '/api/settings/branding'),
    { branding: null },
  );
  await assert.rejects(
    runtime.request(tenant, session, 'PATCH', '/api/settings/branding', {}),
  );
  assert.deepEqual(calls, ['http://127.0.0.1:4311/api/settings/branding']);
});
