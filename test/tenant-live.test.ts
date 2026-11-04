import test from 'node:test';
import assert from 'node:assert/strict';
import {
  tenantApplicationDescriptor,
  tenantSnapshotFromApplication,
  verifiedRotation,
  tenantKeyDigest,
} from '../src/tenant-live.js';
import { bindingDigest } from '@kick-playr/local-key-vault/runtime-client';
const attributes = {
  enabled: true,
  created: 1,
  updated: 1,
  recoveryLevel: 'Purgeable' as const,
};
const binding = {
  environment: 'development',
  tenantId: 'club',
  keyReference: 'workflow-local:club:key',
  variables: {
    wrapping: 'CLUB_WRAPPING_KEY_V1',
    index: 'CLUB_INDEX_KEY',
    control: 'CLUB_CONTROL_KEY',
  },
};
const body = {
  schemaVersion: 1 as const,
  bindingRevision: 3,
  keySets: [
    {
      reference: binding.keyReference,
      mappings: binding.variables,
      currentWrappingVersion: 'v1',
      wrappingVersions: [{ keyVersion: 'v1', vaultVersion: 'a'.repeat(32) }],
      indexVersion: 'b'.repeat(32),
      controlVersion: 'c'.repeat(32),
    },
  ],
  secrets: [],
};
test('tenant legacy metadata descriptor pins physical roles and snapshot conversion retains historical wrapping', () => {
  const descriptor = tenantApplicationDescriptor(binding, {
    ...body,
    bindingDigest: bindingDigest(body),
  });
  assert.equal(descriptor.scope.tenant, 'club');
  const snapshot = {
    ...descriptor,
    resources: descriptor.resources.map((r, i) => ({
      ...r,
      attributes,
      value: Buffer.alloc(32, i + 1).toString('base64'),
    })),
  };
  const converted = tenantSnapshotFromApplication(binding, 7, snapshot);
  assert.equal(converted.bindingRevision, 7);
  assert.equal(converted.keySets[0]?.reference, binding.keyReference);
  assert.equal(converted.keySets[0]?.index.vaultVersion, 'b'.repeat(32));
  const originalWrap = converted.keySets[0]!.wrappingVersions[0]!;
  originalWrap.keyVersion = 'v1';
  converted.keySets[0]!.currentWrappingVersion = 'v1';
  const targetVersion = 'f'.repeat(32);
  const rotated = tenantSnapshotFromApplication(
    { ...binding, version: targetVersion },
    8,
    {
      ...snapshot,
      resources: snapshot.resources.map((resource) =>
        resource.mapping === binding.variables.wrapping
          ? {
              ...resource,
              version: targetVersion,
              value: Buffer.alloc(32, 9).toString('base64'),
            }
          : resource,
      ),
    },
    converted,
  );
  assert.equal(rotated.keySets[0]!.currentWrappingVersion, targetVersion);
  assert.equal(rotated.keySets[0]!.wrappingVersions.length, 2);
  assert.equal(
    rotated.keySets[0]!.wrappingVersions.find((w) => w.keyVersion === 'v1')!
      .value,
    originalWrap.value,
  );
  assert.equal(
    rotated.keySets[0]!.wrappingVersions.find(
      (w) => w.keyVersion === targetVersion,
    )!.vaultVersion,
    targetVersion,
  );

  assert.throws(() =>
    tenantSnapshotFromApplication(
      { ...binding, tenantId: 'other' },
      7,
      snapshot,
    ),
  );
});
test('rotation installation requires completed exact target digest, three exact roles and authoritative revision', () => {
  const descriptor = tenantApplicationDescriptor(binding, {
    ...body,
    bindingDigest: bindingDigest(body),
  });
  const target = Object.fromEntries(
    ['wrapping', 'index', 'control'].map((role) => [
      role,
      descriptor.resources.find(
        (r) =>
          r.mapping ===
          binding.variables[role as keyof typeof binding.variables],
      ),
    ]),
  );
  const proof = {
    stage: 'completed',
    scope: descriptor.scope,
    toDigest: tenantKeyDigest(descriptor, binding),
    to: Object.fromEntries(
      Object.entries(target).map(([role, r]) => [
        role,
        { name: r!.name, version: r!.version },
      ]),
    ),
    activatedRevision: 7,
  };
  assert.equal(verifiedRotation(proof, descriptor, binding, 7), true);
  assert.equal(
    verifiedRotation(
      proof,
      {
        ...descriptor,
        digest: 'e'.repeat(64),
        resources: [
          ...descriptor.resources,
          {
            kind: 'secrets',
            name: 'provider',
            mapping: 'RUNTIME_CREDENTIAL_SMTP',
            version: 'e'.repeat(32),
            policy: 'latest',
            classification: 'secret',
            attributes,
          },
        ],
      },
      binding,
      8,
    ),
    true,
  );

  assert.equal(
    verifiedRotation({ ...proof, stage: 'migrating' }, descriptor, binding, 7),
    false,
  );
  assert.equal(verifiedRotation(proof, descriptor, binding, 8), true);
  assert.equal(verifiedRotation(proof, descriptor, binding, 6), false);
  assert.equal(
    verifiedRotation(
      { ...proof, toDigest: 'f'.repeat(64) },
      descriptor,
      binding,
      7,
    ),
    false,
  );
});

test('cold child metadata failures stay scoped, selected retry recovers, and admitted credentials update real readers', async () => {
  const { createTenantControllers } = await import('../src/tenant-live.js');
  const { ExplorerSecrets } = await import('../src/secrets.js');
  const { encodeRuntimeEnvelope } =
    await import('../src/runtime-configuration.js');
  const { createServer } = await import('node:http');
  const { default: request } = await import('supertest');
  let denied = false,
    paused = false,
    badRecovered = false,
    badAttempts = 0,
    rotationProof: unknown = null,
    credential = 'old-provider',
    discoveryUnavailable = false;
  const fullBinding = {
    ...binding,
    version: 'v1',
    controlDatabase: 'control',
    profile: 'workflow-local',
  };
  const badBinding = {
    ...fullBinding,
    tenantId: 'bad',
    keyReference: 'workflow-local:bad:key',
    variables: {
      wrapping: 'BAD_WRAPPING_KEY_V1',
      index: 'BAD_INDEX_KEY',
      control: 'BAD_CONTROL_KEY',
    },
  };
  const { generateKeyPairSync, sign } = await import('node:crypto');
  const realmKeys = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const realm = (tenant: string) => ({ issuer: `https://${tenant}.clerk.accounts.dev`, authorizedParties: [`https://${tenant}.explorer.example`], jwtKey: realmKeys.publicKey.export({type:'spki',format:'pem'}).toString() });
  const routing = (tenant: string) => ({ tenantId: tenant, environment: 'development', hostname: `${tenant}.example`, origin: `https://${tenant}.example` });
  const rootKey = Buffer.alloc(32, 7);
  const metadata = {
    ...body,
    secrets: [
      {
        mapping: 'RUNTIME_CREDENTIAL_SMTP',
        purpose: 'smtp',
        version: 'd'.repeat(32),
      },
    ],
  };
  const pinned = { ...metadata, bindingDigest: bindingDigest(metadata) };
  const base = tenantApplicationDescriptor(binding, pinned);
  const badBody = {
    ...metadata,
    keySets: metadata.keySets.map((set) => ({
      ...set,
      reference: badBinding.keyReference,
      mappings: badBinding.variables,
    })),
  };
  const badPinned = { ...badBody, bindingDigest: bindingDigest(badBody) };
  const badBase = tenantApplicationDescriptor(badBinding, badPinned);
  const descriptor = (selected = base) => {
    const resources = selected.resources.map((r) => ({
      ...r,
      policy: 'latest',
      attributes,
      version:
        r.mapping === 'RUNTIME_CREDENTIAL_SMTP' && credential !== 'old-provider'
          ? 'e'.repeat(32)
          : r.version,
    }));
    const identity = {
      schemaVersion: 2 as const,
      application: 'explorer-api',
      scope: selected.scope,
      resources,
    };
    const canonical = (value: unknown) =>
      JSON.stringify(value, (_k, v) =>
        v && typeof v === 'object' && !Array.isArray(v)
          ? Object.fromEntries(
              Object.entries(v).sort(([a], [b]) =>
                a < b ? -1 : a > b ? 1 : 0,
              ),
            )
          : v,
      );
    return {
      ...identity,
      generation: credential === 'old-provider' ? 1 : 2,
      digest: requireHash(canonical(identity)),
    };
  };
  const { createHash } = await import('node:crypto');
  const requireHash = (value: string) =>
    createHash('sha256').update(value).digest('hex');
  const env = {
    NODE_ENV: 'development',
    SECRETS_KEYS_STRATEGY: 'LOCAL_KEYVAULT',
    LOCAL_KEYVAULT_APPLICATION_TOKEN: 'stable-application-token-'.repeat(2),
  };
  const { createSecretsRuntime } =
    await import('@kick-playr/local-key-vault/runtime-client');
  const sharedBody = {
    schemaVersion: 1 as const,
    bindingRevision: 1,
    keySets: [],
    secrets: [
      {
        mapping: 'CLERK_SECRET_KEY',
        purpose: 'clerk',
        version: '9'.repeat(32),
      },
    ],
  };
  const sharedRequest = {
    ...sharedBody,
    bindingDigest: bindingDigest(sharedBody),
  };
  const metadataFetch: typeof fetch = async (input, init) => {
    const scopeTenant = new Headers(init?.headers).get('x-vault-tenant')!;
    assert.match(
      String(input),
      /\/local\/runtime-access\/explorer-api\/runtime-manifests\/explorer-api(?:\/3)?$/,
    );
    assert.equal(new Headers(init?.headers).get('Authorization'), `Bearer ${env.LOCAL_KEYVAULT_APPLICATION_TOKEN}`);
    if (scopeTenant === 'unassigned') return Response.json({error:{code:'Denied'}}, {status:403});
    if (scopeTenant === '_shared') {
      if (discoveryUnavailable) return Response.json({error:{code:'Unavailable'}}, {status:503});
      return Response.json({
        schemaVersion: 1,
        application: 'explorer-api',
        scope: { environment: 'development', tenant: '_shared' },
        request: sharedRequest,
        tenants: [
          {
            tenant: 'club',
            bindingRevision: 3,
            bindingDigest: pinned.bindingDigest,
          },
          ...(enrolled ? [{
            tenant: 'bad',
            bindingRevision: 3,
            bindingDigest: badPinned.bindingDigest,
          }, { tenant: 'unassigned', bindingRevision: 3, bindingDigest: badPinned.bindingDigest }] : []),
        ],
      });
    }
    if (scopeTenant === 'bad') {
      badAttempts++;
    }
    return Response.json({
      schemaVersion: 1,
      application: 'explorer-api',
      scope: { environment: 'development', tenant: scopeTenant },
      request: scopeTenant === 'bad' ? badPinned : pinned,
      tenants: [],
    });
  };
  const newLegacy = () => createSecretsRuntime({ environment: env, fetch: metadataFetch });
  let legacy = newLegacy();
  let secrets = new ExplorerSecrets('LOCAL_KEYVAULT', env, legacy);
  let enrolled = false;
  const unassigned = { ...badBinding, tenantId: 'unassigned', keyReference: 'workflow-local:unassigned:key' };

  const makeRow = () => encodeRuntimeEnvelope(
    {
      version: 2,
      explorer: {
        issuer: 'https://example.clerk.accounts.dev',
        authorizedParties: ['http://localhost:3002'],
        adminSubjects: ['test'],
        keyBindings: { version: 1, bindings: enrolled ? [fullBinding, badBinding, unassigned] : [fullBinding] },
        clubRuntimes: [routing('club'), ...(enrolled ? [routing('bad'), routing('unassigned')] : [])],
        clubRealms: [realm('club'), ...(enrolled ? [realm('bad'), realm('unassigned')] : [])],
        frontendHosts: Object.fromEntries(['club', ...(enrolled ? ['bad','unassigned'] : [])].map(tenant => [`${tenant}.explorer.example`, { publishableKey:'pk_test_Y2x1YiQ=', secretVariable:`EXPLORER_CLUB_${tenant.toUpperCase()}_CLERK_SECRET_KEY` }])),
        platformHosts: ['localhost:3002'],
      },
    },
    rootKey,
    'control',
  );
  const client = {
    db: () => ({
      collection: (name: string) => ({
        findOne: async (filter: any) =>
          name === 'tenantDefinitions'
            ? {
                hostname: `${filter.id}.example`, aliases: [],
                configRevision: 3,
                status: paused ? 'in-rotation' : 'active',
                secretReferences: {
                  key:
                    filter.id === 'bad'
                      ? badBinding.keyReference
                      : binding.keyReference,
                },
              }
            : name === 'tenantRuntimeAuthorities'
              ? {
                  schema: 1,
                  tenantId: filter.tenantId,
                  environment: filter.environment,
                  configRevision: 3,
                  status: 'active',
                  identityRealm: `https://${filter.tenantId}.clerk.accounts.dev`,
                }
              : makeRow(),
      }),
    }),
  } as any;
  const fetcher: typeof fetch = async (input, init) => {
    const url = new URL(String(input)),
      action = url.pathname.split('/').at(-1);
    if (action === 'mode')
      return Response.json({
        schemaVersion: 2,
        application: 'explorer-api',
        scope: { environment: 'development', tenant: '_shared' },
        mode: 'live',
      });
    if (new Headers(init?.headers).get('x-vault-tenant') === 'bad' && !badRecovered)
      return Response.json({ error: { code: 'Unavailable' } }, { status: 503 });
    if (denied)
      return Response.json({ error: { code: 'Denied' } }, { status: 403 });
    const d = descriptor(
      new Headers(init?.headers).get('x-vault-tenant') === 'bad'
        ? badBase
        : base,
    );
    if (action === 'desired') return Response.json(d);
    if (action === 'snapshot')
      return Response.json({
        ...d,
        resources: d.resources.map((r, i) => ({
          ...r,
          value:
            r.mapping === 'RUNTIME_CREDENTIAL_SMTP'
              ? credential
              : Buffer.alloc(32, i + 1).toString('base64'),
        })),
      });
    if (action === 'in-use') return Response.json({ valid: true });
    if (action === 'register')
      return Response.json({
        instanceId: 'a'.repeat(36),
        proof: 'p'.repeat(43),
        expiresAt: Date.now() + 30000,
      });
    if (action === 'acknowledge')
      return Response.json({ accepted: true, expiresAt: Date.now() + 30000 });
    throw Error('unexpected');
  };
  const makeManager = () =>
    createTenantControllers({
      secrets,
      client,
      database: 'control',
      wrappingKey: rootKey,
      bindings: [fullBinding],
      legacyFactory: () => legacy,
      fetch: fetcher,
      rotationStatus: async () => rotationProof,
    });
  let manager = await makeManager();
  const server = createServer((req, res) => {
    (res as any).status = (code: number) => {
      res.statusCode = code;
      return res;
    };
    (res as any).json = (body: unknown) => res.end(JSON.stringify(body));
    Object.defineProperty(req, 'path', {
      value: new URL(req.url!, 'http://localhost').pathname,
    });
    manager.middleware(req as any, res as any, () => {
      if (req.url?.endsWith('/key-rotation')) {
        res.end('progress');
        return;
      }
      res.end(
        req.url?.includes('/club/')
          ? secrets.secret(
              {
                environment: 'development',
                tenantId: 'club',
                configRevision: 3,
              },
              'vault:RUNTIME_CREDENTIAL_SMTP',
            )
          : 'unrelated',
      );
    });
  });
  try {
    assert.equal(badAttempts, 0);
    discoveryUnavailable = true;
    await assert.rejects(manager.refresh());
    await request(server).get('/api/platform/tenants/development/club/keys').expect(200);
    discoveryUnavailable = false;
    const untouchedEnvironment = { ...process.env };
    enrolled = true;
    await manager.refresh();
    assert.ok(badAttempts > 0, 'new database-owned binding must be discovered');
    assert.equal(manager.status()['development/bad']?.state, 'error');
    const { PublicRealmDirectory } = await import('../src/public-realms.js');
    const { verifyExplorerSession } = await import('../src/auth.js');
    const directory = new PublicRealmDirectory(undefined, () => manager.configuration()!);
    assert.equal(directory.resolve({host:'club.explorer.example'}).club, true);
    assert.throws(() => directory.resolve({host:'bad.explorer.example'}));
    assert.throws(() => directory.resolve({host:'unassigned.explorer.example'}));
    const claims = {iss:realm('bad').issuer,sub:'user_bad',sid:'session',azp:'https://bad.explorer.example',iat:Math.floor(Date.now()/1000),exp:Math.floor(Date.now()/1000)+60};
    const unsigned = [ {alg:'RS256',typ:'JWT',kid:'fixture'}, claims ].map(v => Buffer.from(JSON.stringify(v)).toString('base64url')).join('.');
    const bearer = 'Bearer '+ unsigned + '.' + sign('RSA-SHA256',Buffer.from(unsigned),realmKeys.privateKey).toString('base64url');
    const auth = {issuer:'https://example.clerk.accounts.dev',authorizedParties:['http://localhost:3002'],adminSubjects:['test'],loadClubRealms:()=>manager.configuration()!.clubRealms};
    await assert.rejects(verifyExplorerSession(auth,bearer));
    assert.deepEqual(manager.configuration()!.clubRuntimes.map(row => row.tenantId), ['club']);
    assert.equal(manager.status()['development/unassigned'], undefined);
    assert.equal(secrets.tenantSnapshot({environment:'development',tenantId:'unassigned',configRevision:3}), undefined);
    await request(server)
      .get('/api/platform/tenants/development/bad/keys')
      .expect(503);
    await request(server)
      .get('/api/platform/tenants/development/bad/key-rotation')
      .expect(200);
    await request(server).get('/healthcheck').expect(200);
    assert.equal(
      (
        await request(server)
          .get('/api/platform/tenants/development/club/keys')
          .expect(200)
      ).text,
      'old-provider',
    );
    badRecovered = true;
    const enrollmentStarted = performance.now();
    const enrollmentPid = process.pid;
    while (!secrets.tenantSnapshot({ environment: 'development', tenantId: 'bad', configRevision: 3 }) && performance.now() - enrollmentStarted < 4500) {
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    assert.ok(secrets.tenantSnapshot({ environment: 'development', tenantId: 'bad', configRevision: 3 }), 'polling must stage new tenant without a request');
    assert.equal(manager.status()['development/bad']?.state, 'ready');
    assert.equal(directory.resolve({host:'bad.explorer.example'}).club, true);
    assert.equal((await verifyExplorerSession(auth,bearer)).issuer, realm('bad').issuer);
    assert.throws(() => directory.resolve({host:'unassigned.explorer.example'}));
    assert.equal(process.pid, enrollmentPid);
    assert.ok(performance.now() - enrollmentStarted < 4500);
    assert.ok(JSON.stringify({ ...process.env }) === JSON.stringify(untouchedEnvironment), 'enrollment must not mutate process.env');
    await request(server)
      .get('/api/platform/tenants/development/bad/keys')
      .expect(200);
    assert.equal(
      secrets.describe(badBinding, 3).versions.index,
      'b'.repeat(32),
    );
    credential = 'new-provider';
    const start = performance.now();
    while (performance.now() - start < 4500) {
      const result = await request(server)
        .get('/api/platform/tenants/development/club/keys')
        .expect(200);
      if (result.text === 'new-provider') break;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.equal(
      secrets.secret(
        { environment: 'development', tenantId: 'club', configRevision: 3 },
        'vault:RUNTIME_CREDENTIAL_SMTP',
      ),
      'new-provider',
    );
    denied = true;
    await new Promise((resolve) => setTimeout(resolve, 1100));
    await request(server)
      .get('/api/platform/tenants/development/club/keys')
      .expect(503);
    await request(server)
      .get('/api/platform/tenants/development/cl%75b/keys')
      .expect(503);
    await request(server)
      .get('/API/PLATFORM/TENANTS/development/club/keys')
      .expect(503);
    assert.equal(
      (await request(server).get('/healthcheck').expect(200)).text,
      'unrelated',
    );
    manager.close();
    secrets.close();
    denied = false;
    paused = true;
    rotationProof = { stage: 'pending' };
    legacy = newLegacy();
    secrets = new ExplorerSecrets('LOCAL_KEYVAULT', env, legacy);
    manager = await makeManager(); // A cold graph starts while its one tenant remains paused.
    assert.equal(
      (
        await request(server)
          .get('/api/platform/tenants/development/club/key-rotation')
          .expect(200)
      ).text,
      'progress',
    );
    await request(server)
      .get('/api/platform/tenants/development/club/keys')
      .expect(503);
    assert.equal(
      (await request(server).get('/healthcheck').expect(200)).text,
      'unrelated',
    );
  } finally {
    manager.close();
    secrets.close();
    server.close();
  }
});

test('durable proof builds key-only exact pins retaining initial aliases without publishing a v1 manifest', async () => {
  const { rotationSnapshotRequest } = await import('../src/tenant-live.js');
  const descriptor = tenantApplicationDescriptor(binding, {
    ...body,
    bindingDigest: bindingDigest(body),
  });
  const to = Object.fromEntries(
    ['wrapping', 'index', 'control'].map((role) => {
      const resource = descriptor.resources.find(
        (r) =>
          r.mapping ===
          binding.variables[role as keyof typeof binding.variables],
      )!;
      return [role, { name: resource.name, version: resource.version }];
    }),
  );
  const proof = {
    stage: 'completed',
    scope: descriptor.scope,
    activatedRevision: 4,
    toDigest: tenantKeyDigest(descriptor, binding),
    to,
    wrappingKeyVersion: to.wrapping!.version,
    wrappingHistory: [
      { keyVersion: 'v1', name: to.wrapping!.name, version: 'f'.repeat(32) },
    ],
  };
  const selected = { ...binding, version: proof.wrappingKeyVersion };
  const request = rotationSnapshotRequest(selected, proof, 5);
  assert.deepEqual(request.secrets, []);
  assert.equal(request.bindingRevision, 5);
  assert.deepEqual(
    request.keySets[0]?.wrappingVersions.map((w) => w.keyVersion),
    [proof.wrappingKeyVersion, 'v1'].sort(),
  );
  assert.throws(() =>
    rotationSnapshotRequest({ ...selected, version: 'v1' }, proof, 5),
  );
  assert.throws(() =>
    rotationSnapshotRequest(selected, { ...proof, stage: 'pending' }, 5),
  );
});

test('retained historical wrapping expiry is checked on every tenant admission', async () => {
  const { validTenantSnapshot } = await import('../src/tenant-live.js');
  const descriptor = tenantApplicationDescriptor(binding, {
    ...body,
    bindingDigest: bindingDigest(body),
  });
  const snapshot = tenantSnapshotFromApplication(binding, 3, {
    ...descriptor,
    resources: descriptor.resources.map((r, i) => ({
      ...r,
      attributes,
      value: Buffer.alloc(32, i + 1).toString('base64'),
    })),
  });
  assert.equal(validTenantSnapshot(snapshot), true);
  snapshot.keySets[0]!.wrappingVersions.push({
    keyVersion: 'historical',
    vaultVersion: 'f'.repeat(32),
    value: Buffer.alloc(32, 8).toString('base64'),
    attributes: { ...attributes, exp: Math.floor(Date.now() / 1000) - 1 },
  });
  assert.equal(validTenantSnapshot(snapshot), false);
});

test('installed SDK accepts index-only rotation retaining v1 and UUID aliases for the same immutable wrapping bytes', async () => {
  const { rotationSnapshotRequest, tenantKeyDigest } =
    await import('../src/tenant-live.js');
  const { parseSnapshotRequest } =
    await import('@kick-playr/local-key-vault/runtime-client');
  const descriptor = tenantApplicationDescriptor(binding, {
    ...body,
    bindingDigest: bindingDigest(body),
  });
  const rotated = {
    ...descriptor,
    resources: descriptor.resources.map((r) =>
      r.mapping === binding.variables.index
        ? { ...r, version: 'e'.repeat(32) }
        : r,
    ),
  };
  const to = Object.fromEntries(
    ['wrapping', 'index', 'control'].map((role) => {
      const r = rotated.resources.find(
        (r) =>
          r.mapping ===
          binding.variables[role as keyof typeof binding.variables],
      )!;
      return [role, { name: r.name, version: r.version }];
    }),
  );
  const proof = {
    stage: 'completed',
    scope: descriptor.scope,
    activatedRevision: 4,
    toDigest: tenantKeyDigest(rotated, binding),
    to,
    wrappingKeyVersion: to.wrapping!.version,
    wrappingHistory: [
      {
        keyVersion: 'v1',
        name: to.wrapping!.name,
        version: to.wrapping!.version,
      },
    ],
  };
  const request = rotationSnapshotRequest(
    { ...binding, version: proof.wrappingKeyVersion },
    proof,
    4,
  );
  assert.equal(
    parseSnapshotRequest(request).keySets[0]!.wrappingVersions.length,
    2,
  );
  assert.equal(
    new Set(request.keySets[0]!.wrappingVersions.map((w) => w.vaultVersion))
      .size,
    1,
  );
  assert.throws(() =>
    rotationSnapshotRequest(
      { ...binding, version: proof.wrappingKeyVersion },
      {
        ...proof,
        wrappingHistory: [
          {
            keyVersion: proof.wrappingKeyVersion,
            name: to.wrapping!.name,
            version: 'f'.repeat(32),
          },
        ],
      },
      4,
    ),
  );
});
