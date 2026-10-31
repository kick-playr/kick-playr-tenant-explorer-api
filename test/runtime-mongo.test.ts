import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { keyBindingProof } from '../src/key-binding-proof.js';
import { KeyFileRegistry } from '../src/key-files.js';
import { RuntimeMongoService } from '../src/runtime-mongo.js';
import {
  encodeRuntimeEnvelope,
  decodeRuntimeEnvelope,
} from '../src/runtime-configuration.js';
const control = 'app-local-real-control-kick-playr-ch';
const uri = (db: string) =>
  `mongodb://user:PRIVATE_PASSWORD@cluster.invalid/${db}?tls=true&authSource=admin`;
function fixture(registered = false) {
  const key = randomBytes(32),
    scope = { environment: 'development', tenantId: 'demo' },
    actor = { subject: 'operator', expiresAt: Date.now() + 60000 };
  const payload: any = {
    version: 2,
    profile: 'workflow-real',
    tenants: registered
      ? [
          {
            id: 'demo',
            mongoUri: uri('old-demo'),
            clerkSecret: 'KEEP_SECRET',
            runtimePolicy: { keep: true },
          },
        ]
      : [],
    explorer: { keyBindings: { version: 1, bindings: [] } },
    other: { keep: 'OTHER_SECRET' },
  };
  const rows: any = {
    tenantWorkflowConfiguration: [encodeRuntimeEnvelope(payload, key, control)],
    tenantDefinitions: [
      {
        id: 'demo',
        environment: 'development',
        status: 'provisioning',
        configRevision: 1,
        secretReferences: {
          mongoUri: 'workflow-local:demo:mongo',
          key: 'workflow-local:demo:key',
        },
      },
    ],
    tenantRuntimeAuthorities: [
      {
        tenantId: 'demo',
        environment: 'development',
        schema: 1,
        status: 'disabled',
        configRevision: 1,
        authorityRevision: 1,
        supportRevision: 1,
        users: [],
        services: [],
      },
    ],
    tenantManagerInvitations: [
      {
        _id: 'development/demo',
        revision: 1,
        invitations: [],
        principals: [],
        onboarding: { provisioning: { configRevision: 1 } },
      },
    ],
    tenantExplorerAudit: [],
  };
  let refuseReplace = false;
  let expireOnAudit = false;
  const match = (row: any, filter: any) =>
    Object.entries(filter).every(
      ([k, v]) => JSON.stringify(row[k]) === JSON.stringify(v),
    );
  const collection = (name: string) => ({
    findOne: async (filter: any, opts: any = {}) =>
      (opts.session?.rows ?? rows)[name]?.find((row: any) =>
        match(row, filter),
      ) ?? null,
    replaceOne: async (filter: any, value: any, opts: any) => {
      assert.ok(opts.session);
      if (refuseReplace) return { matchedCount: 0 };
      const data = opts.session.rows[name],
        index = data.findIndex((r: any) => match(r, filter));
      if (index < 0) return { matchedCount: 0 };
      data[index] = structuredClone(value);
      return { matchedCount: 1 };
    },
    updateOne: async (filter: any, change: any, opts: any) => {
      assert.ok(opts.session);
      const row = opts.session.rows[name].find((r: any) => match(r, filter));
      if (!row) return { matchedCount: 0 };
      for (const [field, n] of Object.entries(change.$inc ?? {}))
        row[field] = (row[field] ?? 0) + Number(n);
      return { matchedCount: 1 };
    },
    insertOne: async (value: any, opts: any) => {
      assert.ok(opts.session);
      if (name === 'tenantExplorerAudit' && expireOnAudit)
        actor.expiresAt = Date.now() - 1;
      opts.session.rows[name].push(structuredClone(value));
    },
  });
  const client: any = {
    db: (db: string) => {
      assert.equal(db, control);
      return { collection };
    },
    startSession: () => {
      const session: any = {
        rows: null,
        withTransaction: async (work: () => Promise<unknown>) => {
          session.rows = structuredClone(rows);
          const result = await work();
          for (const k of Object.keys(rows)) rows[k] = session.rows[k];
          return result;
        },
        endSession: async () => {},
      };
      return session;
    },
  };
  const environment = {
    WORKFLOW_REAL_DEMO_WRAPPING_KEY_V1: randomBytes(32).toString('base64'),
    WORKFLOW_REAL_DEMO_INDEX_KEY: randomBytes(32).toString('base64'),
    WORKFLOW_REAL_DEMO_CONTROL_KEY: randomBytes(32).toString('base64'),
  };
  let mismatch = false;
  const proofOptions = { lifetime: 20000, tenantId: 'demo' };
  const runtime: any = {
    request: async (_scope: any, _actor: any, action: any, input: any) => {
      assert.equal(action, 'key-check');
      const binding = {
        ...scope,
        tenantId: proofOptions.tenantId,
        configRevision: 1,
        keyReference: 'workflow-local:demo:key',
        expiresAt: Date.now() + proofOptions.lifetime,
      };
      const variables = {
        wrapping: 'WORKFLOW_REAL_DEMO_WRAPPING_KEY_V1',
        index: 'WORKFLOW_REAL_DEMO_INDEX_KEY',
        control: 'WORKFLOW_REAL_DEMO_CONTROL_KEY',
      };
      return {
        ...binding,
        variables,
        proofs: Object.fromEntries(
          Object.entries(variables).map(([kind, name]) => [
            kind,
            keyBindingProof(
              Buffer.from(
                mismatch
                  ? randomBytes(32).toString('base64')
                  : environment[name as keyof typeof environment],
                'base64',
              ),
              binding,
              input.challenge,
              kind as any,
              name,
            ),
          ]),
        ),
      };
    },
  };
  const service = new RuntimeMongoService(
    client,
    control,
    key,
    uri(control),
    environment,
    runtime,
  );
  const plain = () =>
    decodeRuntimeEnvelope(
      rows.tenantWorkflowConfiguration[0],
      key,
      control,
    ) as any;
  return {
    service,
    environment,
    proofOptions,
    mismatch: () => {
      mismatch = true;
    },
    rows,
    scope,
    actor,
    plain,
    key,
    expireBeforeCommit: () => {
      expireOnAudit = true;
    },
    conflict: () => {
      refuseReplace = true;
    },
  };
}
test('saves a new tenant URL as an encrypted pending draft, never echoes it, preserves other configuration and invalidates readiness', async () => {
  const f = fixture();
  try {
    const before = await f.service.status(f.scope);
    const saved = await f.service.save(
      f.scope,
      { uri: uri('private-demo'), expectedRevision: before.revision },
      f.actor,
    );
    assert.equal(saved.configured, true);
    assert.equal(saved.source, 'pending');
    assert.ok(!JSON.stringify(saved).includes('PRIVATE_PASSWORD'));
    assert.ok(
      !JSON.stringify(f.rows.tenantWorkflowConfiguration).includes(
        'PRIVATE_PASSWORD',
      ),
    );
    assert.deepEqual(f.plain().pendingMongoBindings, [
      { tenantId: 'demo', mongoUri: uri('private-demo') },
    ]);
    assert.deepEqual(f.plain().other, { keep: 'OTHER_SECRET' });
    assert.equal(
      f.rows.tenantManagerInvitations[0].onboarding.provisioning,
      undefined,
    );
    assert.equal(f.rows.tenantExplorerAudit.length, 1);
    assert.ok(
      !JSON.stringify(f.rows.tenantExplorerAudit).includes('PRIVATE_PASSWORD'),
    );
    await assert.rejects(
      f.service.save(
        f.scope,
        { uri: uri('different-demo'), expectedRevision: before.revision },
        f.actor,
      ),
    );
  } finally {
    f.service.onModuleDestroy();
  }
});
test('updates a registered provisioning row while preserving Clerk/policy data', async () => {
  const f = fixture(true);
  try {
    const status = await f.service.status(f.scope);
    await f.service.save(
      f.scope,
      { uri: uri('new-demo'), expectedRevision: status.revision },
      f.actor,
    );
    assert.equal(f.plain().tenants[0].mongoUri, uri('new-demo'));
    assert.equal(f.plain().tenants[0].clerkSecret, 'KEEP_SECRET');
    assert.deepEqual(f.plain().tenants[0].runtimePolicy, { keep: true });
  } finally {
    f.service.onModuleDestroy();
  }
});
for (const invalid of [
  uri(control),
  uri('admin'),
  uri(''),
  uri('data').replace('cluster.invalid', 'foreign.invalid'),
  uri('data').replace('tls=true', 'tls=false'),
  'https://evil.invalid/data',
])
  test(
    'rejects unsafe URL without changing ciphertext: ' +
      invalid.replace('PRIVATE_PASSWORD', 'REDACTED'),
    async () => {
      const f = fixture();
      try {
        const before = JSON.stringify(f.rows),
          status = await f.service.status(f.scope);
        await assert.rejects(
          f.service.save(
            f.scope,
            { uri: invalid, expectedRevision: status.revision },
            f.actor,
          ),
        );
        assert.equal(JSON.stringify(f.rows), before);
      } finally {
        f.service.onModuleDestroy();
      }
    },
  );
for (const reason of [
  'active',
  'invited',
  'principal',
  'grant',
  'expired',
  'conflict',
])
  test('rejects ' + reason + ' before configuration can commit', async () => {
    const f = fixture();
    try {
      const status = await f.service.status(f.scope);
      if (reason === 'active') f.rows.tenantDefinitions[0].status = 'active';
      if (reason === 'invited')
        f.rows.tenantManagerInvitations[0].invitations.push({
          state: 'pending',
        });
      if (reason === 'principal')
        f.rows.tenantManagerInvitations[0].principals.push({
          state: 'setup-only',
        });
      if (reason === 'grant')
        f.rows.tenantRuntimeAuthorities[0].users.push({ status: 'active' });
      if (reason === 'expired') f.actor.expiresAt = Date.now() - 1;
      if (reason === 'conflict') f.conflict();
      const before = JSON.stringify(f.rows);
      await assert.rejects(
        f.service.save(
          f.scope,
          { uri: uri('new-demo'), expectedRevision: status.revision },
          f.actor,
        ),
      );
      assert.equal(JSON.stringify(f.rows), before);
    } finally {
      f.service.onModuleDestroy();
    }
  });

test('creates a setup revision for the first URL draft before any invitation state exists', async () => {
  const f = fixture();
  try {
    f.rows.tenantManagerInvitations = [];
    const status = await f.service.status(f.scope);
    const saved = await f.service.save(
      f.scope,
      { uri: uri('first-demo'), expectedRevision: status.revision },
      f.actor,
    );
    assert.equal(saved.onboardingRevision, 1);
    assert.equal(f.rows.tenantManagerInvitations[0].revision, 1);
  } finally {
    f.service.onModuleDestroy();
  }
});
test('rejects a database already registered to another tenant or pending draft', async () => {
  for (const pending of [false, true]) {
    const f = fixture();
    try {
      const root = f.plain();
      if (pending)
        root.pendingMongoBindings = [
          { tenantId: 'other', mongoUri: uri('taken-db') },
        ];
      else root.tenants.push({ id: 'other', mongoUri: uri('taken-db') });
      f.rows.tenantWorkflowConfiguration[0] = encodeRuntimeEnvelope(
        root,
        f.key,
        control,
      );
      const status = await f.service.status(f.scope),
        before = JSON.stringify(f.rows);
      await assert.rejects(
        f.service.save(
          f.scope,
          { uri: uri('TAKEN-DB'), expectedRevision: status.revision },
          f.actor,
        ),
      );
      assert.equal(JSON.stringify(f.rows), before);
    } finally {
      f.service.onModuleDestroy();
    }
  }
});
test('unsupported stages and inline scope overrides cannot write', async () => {
  const f = fixture();
  try {
    assert.equal(
      (await f.service.status({ ...f.scope, environment: 'production' }))
        .available,
      false,
    );
    const status = await f.service.status(f.scope),
      before = JSON.stringify(f.rows);
    await assert.rejects(
      f.service.save(
        { ...f.scope, environment: 'production' },
        { uri: uri('db'), expectedRevision: status.revision },
        f.actor,
      ),
    );
    await assert.rejects(
      f.service.save(
        f.scope,
        {
          uri: uri('db'),
          expectedRevision: status.revision,
          tenantId: 'other',
        },
        f.actor,
      ),
    );
    assert.equal(JSON.stringify(f.rows), before);
  } finally {
    f.service.onModuleDestroy();
  }
});

test('expiry after encrypted write but before commit rolls back the whole transaction', async () => {
  const f = fixture();
  try {
    const status = await f.service.status(f.scope),
      before = JSON.stringify(f.rows);
    f.expireBeforeCommit();
    await assert.rejects(
      f.service.save(
        f.scope,
        { uri: uri('next-demo'), expectedRevision: status.revision },
        f.actor,
      ),
    );
    assert.equal(JSON.stringify(f.rows), before);
  } finally {
    f.service.onModuleDestroy();
  }
});

test('registers matching API keys as encrypted metadata without a runtime row, immediately visible through the existing registry', async () => {
  const f = fixture();
  const registry = new KeyFileRegistry([], control, f.environment, () =>
    f.service.loadKeyBindings(),
  );
  assert.equal(
    (await registry.describe(f.rows.tenantDefinitions[0])).status,
    'unbound',
  );
  const before = await f.service.keyStatus(f.scope);
  assert.equal(before.registered, false);
  assert.equal(before.local!.status, 'connected');
  const result = await f.service.configureKeys(
    f.scope,
    { expectedRevision: before.revision },
    { ...f.actor, issuer: 'https://platform.example' },
  );
  assert.equal(result.registered, true);
  assert.notEqual(result.revision, before.revision);
  assert.equal(result.onboardingRevision, 2);
  const payload = f.plain();
  assert.deepEqual(payload.tenants, []);
  assert.equal(payload.explorer.keyBindings.bindings.length, 1);
  assert.equal(
    payload.explorer.keyBindings.bindings[0].variables.index,
    'WORKFLOW_REAL_DEMO_INDEX_KEY',
  );
  assert.equal(f.rows.tenantRuntimeAuthorities[0].status, 'disabled');
  assert.equal(
    f.rows.tenantManagerInvitations[0].onboarding.provisioning,
    undefined,
  );
  assert.equal(f.rows.tenantExplorerAudit[0].action, 'tenant.keys.configured');
  for (const value of Object.values(f.environment))
    assert.ok(
      !JSON.stringify({ payload, result, rows: f.rows }).includes(value),
    );
  assert.equal(
    (await registry.describe(f.rows.tenantDefinitions[0])).status,
    'connected',
  );
});
for (const failure of [
  'mismatch',
  'expired-proof',
  'foreign-proof',
  'root-key',
  'missing',
  'reused',
  'stale',
  'invited',
  'expired-at-commit',
  'CAS',
] as const)
  test(`key registration rejects ${failure} atomically`, async () => {
    const f = fixture(),
      before = await f.service.keyStatus(f.scope),
      snapshot = structuredClone(f.rows);
    if (failure === 'mismatch') f.mismatch();
    if (failure === 'expired-proof') f.proofOptions.lifetime = -1;
    if (failure === 'foreign-proof') f.proofOptions.tenantId = 'other';
    if (failure === 'root-key')
      f.environment.WORKFLOW_REAL_DEMO_WRAPPING_KEY_V1 =
        f.key.toString('base64');
    if (failure === 'missing') f.environment.WORKFLOW_REAL_DEMO_INDEX_KEY = '';
    if (failure === 'reused')
      f.environment.WORKFLOW_REAL_DEMO_INDEX_KEY =
        f.environment.WORKFLOW_REAL_DEMO_CONTROL_KEY;
    if (failure === 'invited')
      f.rows.tenantManagerInvitations[0].invitations.push({ id: 'existing' });
    if (failure === 'expired-at-commit') f.expireBeforeCommit();
    if (failure === 'CAS') f.conflict();
    const expectedRevision =
      failure === 'stale' ? '0'.repeat(64) : before.revision;
    await assert.rejects(
      f.service.configureKeys(
        f.scope,
        { expectedRevision },
        Object.assign(f.actor, { issuer: 'https://platform.example' }),
      ),
    );
    assert.deepEqual(
      f.rows.tenantWorkflowConfiguration,
      snapshot.tenantWorkflowConfiguration,
    );
    assert.equal(f.rows.tenantExplorerAudit.length, 0);
    assert.equal(f.rows.tenantRuntimeAuthorities[0].authorityRevision, 1);
  });

test('dynamic key metadata keeps supported explorer-only envelopes readable without enabling runtime writes', async () => {
  const f = fixture(),
    payload = f.plain();
  delete payload.profile;
  delete payload.tenants;
  f.rows.tenantWorkflowConfiguration[0] = encodeRuntimeEnvelope(
    payload,
    f.key,
    control,
  );
  assert.deepEqual(await f.service.loadKeyBindings(), []);
  await assert.rejects(f.service.status(f.scope));
});
