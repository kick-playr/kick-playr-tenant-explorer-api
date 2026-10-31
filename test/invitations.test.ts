import test from 'node:test';
import assert from 'node:assert/strict';
import { InvitationService } from '../src/invitations/service.js';
import { CredentialVault } from '../src/vault.js';
import type {
  InvitationState,
  InvitationTransaction,
  Scope,
} from '../src/invitations/types.js';

const scope = { environment: 'development', tenantId: 'club' };
const binding = {
  ...scope,
  issuer: 'https://club.clerk.accounts.dev',
  origin: 'https://club.example',
  audience: 'club',
  authorizedParties: ['https://club.example'],
  secretKey: 'test-only',
};
function fixture() {
  let state: InvitationState = { revision: 0, invitations: [], principals: [] };
  let queue = Promise.resolve();
  const tenant = {
    definition: {
      id: 'club',
      environment: 'development',
      status: 'provisioning',
      configRevision: 1,
      public: { name: 'Club' },
    },
    authority: { identityRealm: binding.issuer, users: [] },
  };
  const repository = {
    async transact<T>(
      s: Scope,
      work: (tx: InvitationTransaction) => Promise<T>,
    ) {
      assert.deepEqual(s, scope);
      const previous = queue;
      let release!: () => void;
      queue = new Promise<void>((r) => {
        release = r;
      });
      await previous;
      try {
        const draft = structuredClone(state);
        const result = await work({
          tenant: structuredClone(tenant),
          state: draft,
        });
        state = draft;
        return result;
      } finally {
        release();
      }
    },
  };
  let actor = {
    issuer: binding.issuer,
    subject: 'user_new',
    sessionId: 'sess',
    emails: ['other@example.ch', 'new@example.ch'],
  };
  const mail: { to: string; url: string }[] = [];
  const service = new InvitationService(
    repository as any,
    [binding],
    {
      verify: async () => actor,
      resolve: async (_b: any, subject: string) => ({ ...actor, subject }),
    },
    new CredentialVault(Buffer.alloc(32, 7)),
    {
      send: async (m: any) => {
        mail.push(m);
      },
    },
  );
  return {
    service,
    mail,
    tenant,
    get state() {
      return state;
    },
    setActor(a: typeof actor) {
      actor = a;
    },
  };
}
const operator = {
  kind: 'platform' as const,
  issuer: 'https://platform.example',
  subject: 'operator',
};
async function invite(f: ReturnType<typeof fixture>) {
  const result = await f.service.create(scope, operator, {
    kind: 'email',
    email: 'new@example.ch',
  });
  await f.service.deliver(scope, operator, result.id);
  return new URL(f.mail[0]!.url).hash.slice(1);
}
test('verified secondary recipient accepts idempotently without runtime access', async () => {
  const f = fixture(),
    token = await invite(f);
  const accepted = await f.service.accept(scope, token, 'bearer');
  assert.equal(accepted.state, 'setup-only');
  assert.deepEqual(await f.service.accept(scope, token, 'bearer'), accepted);
  assert.equal(f.state.principals.length, 1);
  assert.equal(f.tenant.authority.users.length, 0);
  const status = await f.service.status(scope, 'bearer');
  assert.equal(status.state, 'blocked');
  assert.ok(status.missingPrerequisites.includes('app26-unavailable'));
  assert.equal(
    JSON.stringify(await f.service.list(scope, operator)).includes(token),
    false,
  );
  assert.equal(JSON.stringify(f.state).includes(token), false);
});
test('wrong recipient or issuer cannot accept', async () => {
  for (const actor of [
    {
      issuer: binding.issuer,
      subject: 'wrong',
      sessionId: 's',
      emails: ['wrong@example.ch'],
    },
    {
      issuer: 'https://other.example',
      subject: 'user_new',
      sessionId: 's',
      emails: ['new@example.ch'],
    },
  ]) {
    const f = fixture(),
      token = await invite(f);
    f.setActor(actor);
    await assert.rejects(f.service.accept(scope, token, 'bearer'));
    assert.equal(f.state.principals.length, 0);
  }
});
test('resend rotates token; revoked and expired links fail', async () => {
  const f = fixture(),
    old = await invite(f),
    id = f.state.invitations[0]!.id;
  await f.service.resend(scope, operator, id);
  await f.service.deliver(scope, operator, id);
  const fresh = new URL(f.mail[1]!.url).hash.slice(1);
  await assert.rejects(f.service.accept(scope, old, 'bearer'));
  await f.service.revoke(scope, operator, id);
  await assert.rejects(f.service.accept(scope, fresh, 'bearer'));
  const g = fixture(),
    expired = await invite(g);
  g.state.invitations[0]!.expiresAt = 0;
  await assert.rejects(g.service.accept(scope, expired, 'bearer'));
});
test('simultaneous accept creates one owner; second bootstrap invitation denied', async () => {
  const f = fixture(),
    token = await invite(f);
  const results = await Promise.all(
    Array.from({ length: 8 }, () => f.service.accept(scope, token, 'bearer')),
  );
  assert.equal(new Set(results.map((x) => x.membershipId)).size, 1);
  assert.equal(f.state.owner?.subject, 'user_new');
  await assert.rejects(
    f.service.create(scope, operator, {
      kind: 'email',
      email: 'second@example.ch',
    }),
  );
});
test('known subject requires verified email and exact identity', async () => {
  const f = fixture();
  f.setActor({
    issuer: binding.issuer,
    subject: 'user_target',
    sessionId: 's',
    emails: [],
  });
  await assert.rejects(
    f.service.create(scope, operator, {
      kind: 'subject',
      subject: 'user_target',
    }),
  );
  f.setActor({
    issuer: binding.issuer,
    subject: 'user_target',
    sessionId: 's',
    emails: ['target@example.ch'],
  });
  const i = await f.service.create(scope, operator, {
    kind: 'subject',
    subject: 'user_target',
  });
  await f.service.deliver(scope, operator, i.id);
  f.setActor({
    issuer: binding.issuer,
    subject: 'someone',
    sessionId: 's',
    emails: ['target@example.ch'],
  });
  await assert.rejects(
    f.service.accept(scope, new URL(f.mail[0]!.url).hash.slice(1), 'bearer'),
  );
});
test('suspension and revoked principal override acceptance retry', async () => {
  const f = fixture(),
    token = await invite(f);
  await f.service.accept(scope, token, 'bearer');
  f.state.principals[0]!.state = 'revoked';
  await assert.rejects(f.service.accept(scope, token, 'bearer'));
  f.tenant.definition.status = 'suspended';
  await assert.rejects(f.service.status(scope, 'bearer'));
});
test('non-owner cannot manage; failed delivery keeps retryable encrypted intent', async () => {
  const f = fixture();
  await assert.rejects(
    f.service.list(scope, { kind: 'club', token: 'bearer' }),
  );
  const i = await f.service.create(scope, operator, {
    kind: 'email',
    email: 'new@example.ch',
  });
  assert.equal(f.state.invitations[0]!.delivery.status, 'queued');
  assert.equal(
    JSON.stringify(f.state).includes('https://club.example/invitations#'),
    false,
  );
  assert.equal(i.state, 'pending');
});

test('ordinary manager cannot invite; explicit active main-manager role can', async () => {
  const f = fixture(),
    token = await invite(f);
  await f.service.accept(scope, token, 'bearer');
  f.tenant.definition.status = 'active';
  Object.assign(f.tenant.authority, { status: 'active' });
  f.tenant.authority.users.push({
    issuer: binding.issuer,
    subject: 'user_new',
    status: 'active',
  } as never);
  f.state.principals[0]!.state = 'operational';
  f.state.principals[0]!.role = 'manager';
  await assert.rejects(
    f.service.create(
      scope,
      { kind: 'club', token: 'bearer' },
      { kind: 'email', email: 'next@example.ch' },
    ),
  );
  f.state.principals[0]!.role = 'main-manager';
  const i = await f.service.create(
    scope,
    { kind: 'club', token: 'bearer' },
    { kind: 'email', email: 'next@example.ch' },
  );
  assert.equal(i.bootstrap, false);
});
test('delivery failure is durable and retry uses the same message, not a new invitation', async () => {
  const f = fixture(),
    token = await invite(f),
    id = f.state.invitations[0]!.id;
  await f.service.deliver(scope, operator, id);
  assert.equal(f.mail.length, 1);
  const sending = fixture();
  const i = await sending.service.create(scope, operator, {
    kind: 'email',
    email: 'new@example.ch',
  });
  const rejecting = new InvitationService(
    (sending.service as any).repository,
    [binding],
    (sending.service as any).identity,
    new CredentialVault(Buffer.alloc(32, 7)),
    {
      send: async () => {
        throw Error('SMTP credentials must not escape');
      },
    },
  );
  await rejecting.deliver(scope, operator, i.id);
  assert.equal(sending.state.invitations[0]!.delivery.status, 'failed');
  await sending.service.deliver(scope, operator, i.id);
  assert.equal(sending.mail.length, 1);
  assert.equal(sending.state.invitations.length, 1);
  assert.equal(
    JSON.stringify(await sending.service.list(scope, operator)).includes(
      'credentials',
    ),
    false,
  );
  assert.ok(token);
});
test('persisted inviter and tenant rate limits survive repeated requests', async () => {
  const f = fixture();
  for (let n = 0; n < 10; n++)
    await f.service.create(scope, operator, {
      kind: 'email',
      email: 'new@example.ch',
    });
  await assert.rejects(
    f.service.create(scope, operator, {
      kind: 'email',
      email: 'new@example.ch',
    }),
    (e) => (e as any).getStatus() === 429,
  );
  assert.equal(f.state.invitations.length, 1);
});
test('accepted access revocation disables setup identity and runtime record without resurrection', async () => {
  const f = fixture(),
    token = await invite(f),
    id = f.state.invitations[0]!.id;
  await f.service.accept(scope, token, 'bearer');
  await f.service.revokeAccess(scope, operator, id);
  assert.equal(f.state.principals[0]!.state, 'revoked');
  await assert.rejects(f.service.accept(scope, token, 'bearer'));
  await assert.rejects(f.service.status(scope, 'bearer'));
});
