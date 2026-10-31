import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ClerkInvitationIdentity,
  invitationBindings,
} from '../src/invitations/identity.js';
const binding = {
  environment: 'production',
  tenantId: 'club',
  issuer: 'https://club.clerk.accounts.dev',
  origin: 'https://club.example',
  audience: 'club',
  authorizedParties: ['https://club.example'],
  secretKey: 'test-secret',
};
test('invitation backend secret references cannot use browser-public variable names', () => {
  const { secretKey, ...publicBinding } = binding;
  assert.throws(() =>
    invitationBindings(
      JSON.stringify([
        { ...publicBinding, secretKeyEnv: 'NEXT_PUBLIC_CLUB_SECRET' },
      ]),
      { NEXT_PUBLIC_CLUB_SECRET: secretKey },
    ),
  );
});
test('setup verification passes exact expected JWT constraints and checks live session/user', async () => {
  const claims = {
    iss: binding.issuer,
    sub: 'user_new',
    sid: 'sess',
    azp: binding.origin,
    exp: Date.now() / 1000 + 60,
    nbf: Date.now() / 1000 - 5,
  };
  const session = { id: 'sess', userId: 'user_new', status: 'active' },
    user = {
      id: 'user_new',
      banned: false,
      locked: false,
      emailAddresses: [
        {
          emailAddress: 'not@example.ch',
          verification: { status: 'unverified' },
        },
        {
          emailAddress: 'secondary@example.ch',
          verification: { status: 'verified' },
        },
      ],
    };
  const verifier = new ClerkInvitationIdentity({
    verifyToken: async (_token: string, options: any) => {
      assert.equal(options.audience, 'club');
      assert.deepEqual(options.authorizedParties, [binding.origin]);
      return claims;
    },
    createClerkClient: () => ({
      sessions: { getSession: async () => session },
      users: { getUser: async () => user },
    }),
  } as any);
  assert.deepEqual((await verifier.verify(binding, 'aaa.bbb.ccc')).emails, [
    'secondary@example.ch',
  ]);
  for (const patch of [
    { iss: 'https://wrong.example' },
    { azp: 'https://wrong.example' },
    { exp: 1 },
  ]) {
    const original = { ...claims };
    Object.assign(claims, patch);
    await assert.rejects(verifier.verify(binding, 'aaa.bbb.ccc'));
    Object.assign(claims, original);
  }
  session.status = 'revoked';
  await assert.rejects(verifier.verify(binding, 'aaa.bbb.ccc'));
  session.status = 'active';
  user.banned = true;
  await assert.rejects(verifier.verify(binding, 'aaa.bbb.ccc'));
  user.banned = false;
  session.userId = 'different';
  await assert.rejects(verifier.verify(binding, 'aaa.bbb.ccc'));
});
test('bindings require exact secure origins, unique scope and explicit secret reference', () => {
  const { secretKey, ...rest } = binding,
    raw = JSON.stringify([{ ...rest, secretKeyEnv: 'CLUB_SECRET' }]);
  assert.equal(
    invitationBindings(raw, { CLUB_SECRET: secretKey })[0]!.issuer,
    binding.issuer,
  );
  assert.throws(() => invitationBindings(raw, {}));
  assert.throws(() =>
    invitationBindings(
      JSON.stringify([
        {
          ...rest,
          origin: 'https://club.example/path',
          secretKeyEnv: 'CLUB_SECRET',
        },
      ]),
      { CLUB_SECRET: secretKey },
    ),
  );
  assert.throws(() =>
    invitationBindings(
      JSON.stringify([
        { ...rest, secretKeyEnv: 'CLUB_SECRET' },
        { ...rest, secretKeyEnv: 'CLUB_SECRET' },
      ]),
      { CLUB_SECRET: secretKey },
    ),
  );
});

test('provider waits cannot extend a signed proof past expiration', async () => {
  const now = Date.now(),
    original = Date.now;
  const verifier = new ClerkInvitationIdentity({
    verifyToken: async () => ({
      iss: binding.issuer,
      sub: 'user_new',
      sid: 'sess',
      azp: binding.origin,
      exp: now / 1000 + 1,
      nbf: now / 1000 - 5,
    }),
    createClerkClient: () => ({
      sessions: {
        getSession: async () => {
          Date.now = () => now + 2000;
          return { id: 'sess', userId: 'user_new', status: 'active' };
        },
      },
      users: {
        getUser: async () => ({
          id: 'user_new',
          banned: false,
          locked: false,
          emailAddresses: [],
        }),
      },
    }),
  } as any);
  try {
    await assert.rejects(verifier.verify(binding, 'aaa.bbb.ccc'));
  } finally {
    Date.now = original;
  }
});

test('operator live-session check also rejects expiration after provider waits', async () => {
  const { assertLivePlatformSession } =
    await import('../src/invitations/controller.js');
  const claims = {
    iss: binding.issuer,
    sub: 'user_operator',
    sid: 'sess',
    exp: Date.now() / 1000 + 60,
  };
  const session = { id: 'sess', userId: 'user_operator', status: 'active' },
    user = { id: 'user_operator', banned: false, locked: false };
  assert.doesNotThrow(() =>
    assertLivePlatformSession(
      claims,
      session,
      user,
      binding.issuer,
      'user_operator',
    ),
  );
  claims.exp = 1;
  assert.throws(() =>
    assertLivePlatformSession(
      claims,
      session,
      user,
      binding.issuer,
      'user_operator',
    ),
  );
});
