import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ClubController } from '../src/club.controller.js';
import { oauthCallbackPath } from '../src/oauth-callback.js';
test('callback validates provider, issuer and unique scalar state/code fields',()=>{
  const query={state:'oauth1.'+'a'.repeat(43),code:'code'};
  assert.ok(oauthCallbackPath('bexio',query).startsWith('/bexio/oauth/callback?'));
  for(const invalid of [{...query,code:['a','b']},{...query,iss:'https://evil.example'},{...query,url:'https://evil.example'},{...query,state:''}]) assert.throws(()=>oauthCallbackPath('bexio',invalid));
});
test('Explorer preserves the current session when starting and finishing OAuth',async()=>{
  const session={issuer:'issuer',subject:'admin',token:'current-session-token'}, tenant={id:'fcrww'};
  const calls:any[]=[];
  const clubs={require:async(_e:string,_id:string,identity:unknown)=>{assert.equal(identity,session);return tenant;},audit:async()=>{}};
  const runtime={request:async(...args:any[])=>{calls.push(args);return args[3].endsWith('/signin')?{url:'https://auth.bexio.com/authorize?state=oauth1.'+'a'.repeat(43)}:{connected:true};}};
  const controller=new ClubController(clubs as any,runtime as any);
  const request={query:{},explorerSession:session} as any;
  const start=await controller.connect(request,'development','fcrww','bexio');
  assert.equal(new URL(start.url).searchParams.get('state'),'explorer.oauth1.'+'a'.repeat(43));
  request.query={state:'oauth1.'+'a'.repeat(43),code:'code'};
  assert.deepEqual(await controller.callback(request,'development','fcrww','bexio'),{connected:true});
  assert.equal(calls[1][1],session);
  assert.equal(calls[1][3],oauthCallbackPath('bexio',request.query));
});
