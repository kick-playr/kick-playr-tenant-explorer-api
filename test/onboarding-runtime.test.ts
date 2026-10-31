import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { SetupRuntime } from '../src/onboarding/runtime.js';
const s = { environment: 'development', tenantId: 'fcrww' };
const actor = {
  issuer: 'https://club.clerk.accounts.dev',
  subject: 'user_owner',
  membershipId: 'member',
};
test('setup transport uses only pinned server destination, exact signed body and no browser bearer', async () => {
  let calls = 0;
  const key = Buffer.alloc(32, 7);
  const runtime = new SetupRuntime(
    [{ ...s, origin: 'http://localhost:4312' }],
    key.toString('base64'),
    async (url, options) => {
      calls++;
      assert.equal(url, 'http://localhost:4312/api/internal/manager-setup');
      assert.equal(options!.redirect, 'error');
      assert.equal(options!.cache, 'no-store');
      const raw = String(options!.body);
      const h = new Headers(options!.headers);
      assert.equal(h.has('authorization'), false);
      assert.equal(
        h.get('x-manager-setup-signature'),
        createHmac('sha256', key)
          .update('manager-setup-v1\nPOST\n/api/internal/manager-setup\n')
          .update(raw)
          .digest('base64url'),
      );
      const v = JSON.parse(raw);
      assert.deepEqual(v.scope, s);
      assert.deepEqual(v.actor, actor);
      assert.equal(v.action, 'settings');
      assert.equal(v.expiresAt - v.issuedAt, 30000);
      return Response.json({ settings: { hash: 'revision' } });
    },
  );
  assert.deepEqual(await runtime.request(s, actor, 'settings', {}), {
    settings: { hash: 'revision' },
  });
  await assert.rejects(
    runtime.request({ ...s, tenantId: 'foreign' }, actor, 'settings', {}),
  );
  assert.equal(calls, 1);
});
test('missing setup custody/destination and unsafe origins fail closed', async () => {
  assert.throws(
    () =>
      new SetupRuntime([{ ...s, origin: 'http://remote.example' }], undefined),
  );
  await assert.rejects(
    new SetupRuntime([], undefined).request(s, actor, 'settings', {}),
  );
});
test('setup capability never extends the verified Clerk token expiry',async()=>{
  let expiresAt=0,calls=0;
  const deadline=Date.now()+5000;
  const runtime=new SetupRuntime([{...s,origin:'http://localhost:4312'}],Buffer.alloc(32,7).toString('base64'),async(_url,options)=>{calls++;const request=JSON.parse(String(options!.body));expiresAt=request.expiresAt;assert.equal(request.actor.expiresAt,undefined);return Response.json({});});
  await runtime.request(s,{...actor,expiresAt:deadline},'settings',{});
  assert.ok(expiresAt<=deadline);
  await assert.rejects(runtime.request(s,{...actor,expiresAt:Date.now()-1},'settings',{}));assert.equal(calls,1);
});
