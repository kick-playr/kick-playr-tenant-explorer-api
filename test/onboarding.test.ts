import test from 'node:test';
import assert from 'node:assert/strict';
import { OnboardingService } from '../src/onboarding/service.js';
import type {
  InvitationState,
  InvitationTransaction,
  Scope,
} from '../src/invitations/types.js';
const s = { environment: 'development', tenantId: 'club' };
const binding = {
  ...s,
  issuer: 'https://club.clerk.accounts.dev',
  origin: 'https://club.example',
  audience: 'club',
  authorizedParties: ['https://club.example'],
  secretKey: 'test',
};
function fixture() {
  const state: InvitationState = {
    revision: 1,
    invitations: [],
    owner: { issuer: binding.issuer, subject: 'user_owner' },
    principals: [
      {
        id: 'owner',
        issuer: binding.issuer,
        subject: 'user_owner',
        role: 'owner',
        state: 'setup-only',
      },
      {
        id: 'additional',
        issuer: binding.issuer,
        subject: 'user_next',
        role: 'manager',
        state: 'setup-only',
      },
    ],
  };
  const tenant: InvitationTransaction['tenant'] = {
    definition: {
      id: 'club',
      environment: 'development',
      status: 'provisioning',
      configRevision: 1,
      public: { name: 'Club' },
    },
    authority: { identityRealm: binding.issuer, status: 'disabled', users: [] },
  };
  let subject = 'user_owner',
    publishes = 0,
    calls = 0;
  const repo = {
    async transact<T>(
      _scope: Scope,
      work: (tx: InvitationTransaction) => Promise<T>,
    ): Promise<T> {
      const draft = structuredClone(state);
      const value = await work({
        tenant,
        state: draft,
        publishRuntime: async (input) => {
          publishes++;
          tenant.definition.status = 'active';
          tenant.authority!.status = 'active';
          tenant.authority!.users.push({
            issuer: binding.issuer,
            subject: input.subject,
            status: 'active',
          });
        },
      });
      if (JSON.stringify(state) !== JSON.stringify(draft)) {
        Object.assign(state, draft);
        state.revision++;
      }
      return value;
    },
  };
  const runtime = {
    async request(
      _s: Scope,
      _a: unknown,
      action: string,
      input: Record<string, unknown>,
    ) {
      calls++;
      if (action === 'provisioning')
        return {
          checks: {
            mongodb: 'verified',
            keys: 'verified',
            runtime: 'verified',
          },
        };
      if (action === 'verify')
        return {
          proofId: 'proof',
          accountReference: 'account',
          settingsHash: 'settings-hash',
        };
      if (action === 'contact')
        return {
          contact: { id: input.contactId, name: 'Existing' },
          accountReference: 'account',
        };
      return { settings: { hash: 'settings-hash' }, connected: true };
    },
  };
  const identity = {
    async verify() {
      return {
        issuer: binding.issuer,
        subject,
        sessionId: 'session',
        emails: ['verified@example.ch'],
      };
    },
    async resolve() {
      throw Error('not used');
    },
  };
  const service = new OnboardingService(repo, [binding], identity, runtime);
  return {
    service,
    state,
    tenant,
    repo,
    runtime,
    identity,
    setSubject: (v: string) => {
      subject = v;
    },
    publishes: () => publishes,
    calls: () => calls,
  };
}
test('onboarding saves/resumes and owner publication is idempotent', async () => {
  const f = fixture();
  const initial = await f.service.status(s, 'token');
  assert.equal(initial.nextStep, 'settings');
  assert.equal(initial.operationalAccess, false);
  const saved = await f.service.run(s, 'token', 'save-settings', {
    expectedRevision: 1,
    patch: { currentSaison: '26.2' },
    expectedHash: 'before',
  });
  assert.equal(saved.nextStep, 'bexio');
  await f.service.run(s, 'token', 'contact', {
    contactId: 42,
    expectedRevision: f.state.revision,
  });
  const done = await f.service.complete(s, 'token', f.state.revision);
  assert.equal(done.operationalAccess, true);
  assert.equal(done.nextDestination, '/');
  assert.equal(f.publishes(), 1);
  assert.equal(
    (await f.service.complete(s, 'token', f.state.revision)).operationalAccess,
    true,
  );
  assert.equal(f.publishes(), 1);
});
test('additional manager is blocked until owner finishes and requires confirmed contact', async () => {
  const f = fixture();
  f.setSubject('user_next');
  assert.deepEqual((await f.service.status(s, 'token')).missingPrerequisites, [
    'first-manager-onboarding',
  ]);
  await assert.rejects(f.service.run(s, 'token', 'contacts', {}));
  assert.equal(f.calls(), 0);
  f.setSubject('user_owner');
  await f.service.run(s, 'token', 'save-settings', {
    expectedRevision: f.state.revision,
    expectedHash: 'before',
    patch: { currentSaison: '26.1' },
  });
  await f.service.run(s, 'token', 'contact', {
    contactId: 42,
    expectedRevision: f.state.revision,
  });
  await f.service.complete(s, 'token', f.state.revision);
  f.setSubject('user_next');
  await f.service.run(s, 'token', 'contact', {
    contactId: 43,
    expectedRevision: f.state.revision,
  });
  await assert.rejects(f.service.complete(s, 'token', f.state.revision));
  f.setSubject('user_owner');
  await f.service.confirm(s, 'token', {
    membershipId: 'additional',
    contactId: 43,
    expectedRevision: f.state.revision,
  });
  f.setSubject('user_next');
  assert.equal(
    (await f.service.complete(s, 'token', f.state.revision)).operationalAccess,
    true,
  );
});
test('revoked users, suspended tenants, stale revisions and foreign scopes cannot configure or publish', async () => {
  const f = fixture();
  await assert.rejects(
    f.service.run(s, 'token', 'contact', {
      contactId: 42,
      expectedRevision: 0,
    }),
  );
  assert.equal(f.calls(), 0);
  await assert.rejects(f.service.status({ ...s, tenantId: 'other' }, 'token'));
  f.state.principals[0]!.state = 'revoked';
  await assert.rejects(f.service.status(s, 'token'));
  f.state.principals[0]!.state = 'setup-only';
  f.tenant.definition.status = 'suspended';
  await assert.rejects(f.service.status(s, 'token'));
  assert.equal(f.publishes(), 0);
});
test('missing publisher fails closed and never promotes a setup principal', async () => {
  const f = fixture();
  const service = new OnboardingService(
    {
      transact: async (_s, work) => work({ tenant: f.tenant, state: f.state }),
    },
    [binding],
    {
      verify: async () => ({
        issuer: binding.issuer,
        subject: 'user_owner',
        sessionId: 'session',
        emails: ['verified@example.ch'],
      }),
      resolve: async () => {
        throw Error();
      },
    },
    {
      request: async (_s, _a, action, input) =>
        action === 'contact'
          ? { contact: { id: input.contactId }, accountReference: 'account' }
          : {
              proofId: 'proof',
              accountReference: 'account',
              settingsHash: 'settings-hash',
            },
    },
  );
  f.state.onboarding = {
    policyVersion: 'manager-setup-v1',
    progress: { owner: { step: 'settings', settingsHash: 'settings-hash' } },
  };
  await service.run(s, 'token', 'contact', {
    contactId: 42,
    expectedRevision: 1,
  });
  await assert.rejects(service.complete(s, 'token', f.state.revision));
  assert.equal(f.state.principals[0]!.state, 'setup-only');
});
test('manual provisioning saves progress but only verified infrastructure plus SMTP permits first invitation', async () => {
  const f = fixture();
  let verified = 0,
    sent = 0;
  const service = new OnboardingService(
    f.repo,
    [binding],
    f.identity,
    f.runtime,
    {
      ready: true,
      verify: async () => {
        verified++;
        return true;
      },
      send: async () => {
        sent++;
      },
    },
  );
  const operator = { issuer: 'https://platform.example', subject: 'operator' };
  await service.saveProvisioning(s, operator, {
    expectedRevision: 1,
    steps: ['clerk', 'claims'],
  });
  await assert.rejects(service.assertProvisioned(s));
  assert.deepEqual((await service.provisioning(s)).operatorSteps, [
    'clerk',
    'claims',
  ]);
  await service.verifyProvisioning(s, operator);
  await service.assertProvisioned(s);
  assert.equal(verified, 1);
  assert.equal(sent, 0);
  f.tenant.definition.configRevision++;
  await assert.rejects(service.assertProvisioned(s));
});
test('changed Bexio account or settings between selection and completion cannot publish a grant', async () => {
  for (const changed of ['account', 'settings']) {
    const f = fixture();
    await f.service.run(s, 'token', 'save-settings', {
      expectedRevision: 1,
      expectedHash: 'before',
      patch: { currentSaison: '26.1' },
    });
    await f.service.run(s, 'token', 'contact', {
      contactId: 42,
      expectedRevision: f.state.revision,
    });
    const request = f.runtime.request.bind(f.runtime);
    f.runtime.request = async (scope, actor, action, input) =>
      action === 'verify'
        ? {
            proofId: 'proof',
            accountReference:
              changed === 'account' ? 'other-account' : 'account',
            settingsHash:
              changed === 'settings' ? 'other-hash' : 'settings-hash',
          }
        : request(scope, actor, action, input);
    await assert.rejects(f.service.complete(s, 'token', f.state.revision));
    assert.equal(f.publishes(), 0);
    assert.equal(f.state.principals[0]!.state, 'setup-only');
  }
});
test('Bexio client secret never enters wizard progress and only owner may configure it', async () => {
  const f = fixture();
  const secret = 'SECRET-CANARY';
  await f.service.run(s, 'token', 'bexio-configure', {
    clientId: 'client',
    clientSecret: secret,
    accountReference: 'account',
  });
  assert.doesNotMatch(JSON.stringify(f.state), /SECRET-CANARY/);
  f.state.onboarding = {
    policyVersion: 'manager-setup-v1',
    ownerCompletedAt: new Date().toISOString(),
    progress: {},
  };
  f.setSubject('user_next');
  const before = f.calls();
  await assert.rejects(
    f.service.run(s, 'token', 'bexio-configure', {
      clientId: 'client',
      clientSecret: secret,
      accountReference: 'account',
    }),
  );
  assert.equal(f.calls(), before);
});
test('revocation during a provider response prevents saved progress or operational promotion', async () => {
  const f = fixture();
  f.runtime.request = async () => {
    f.state.principals[0]!.state = 'revoked';
    return {
      contact: { id: 42, name: 'Existing' },
      accountReference: 'account',
    };
  };
  await assert.rejects(
    f.service.run(s, 'token', 'contact', {
      contactId: 42,
      expectedRevision: f.state.revision,
    }),
  );
  assert.equal(f.state.onboarding, undefined);
  assert.equal(f.publishes(), 0);
});

test('MongoDB configuration changes during infrastructure checks invalidate their receipt',async()=>{
 const f=fixture();
 const service=new OnboardingService(f.repo,[binding],f.identity,f.runtime,{ready:true,send:async()=>{},verify:async()=>{f.state.revision++;return true;}});
 await assert.rejects(service.verifyProvisioning(s,{issuer:'https://platform.example',subject:'operator'}));
 assert.equal(f.state.onboarding?.provisioning,undefined);
});
