import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import {
  ownedApplication,
  forwardApplication,
} from '../src/live-application.js';

test('response leases retain captured clients until the response finishes', async () => {
  let disposed = false;
  const app = ownedApplication({
    handler: (_req, res) => {
      (res as any).credential = 'new-clerk';
    },
    close: async () => {
      disposed = true;
    },
  });
  const response = new EventEmitter() as any;
  const lease = forwardApplication(
    app,
    {} as any,
    response,
    new AbortController().signal,
  );
  assert.equal(response.credential, 'new-clerk');
  const close = app.close();
  await Promise.resolve();
  assert.equal(disposed, false);
  response.emit('finish');
  await lease;
  await close;
  assert.equal(disposed, true);
});

test('aborted HTTP leases destroy the response and release old clients', async () => {
  let disposed = false;
  const app = ownedApplication({
    handler: () => {},
    close: async () => {
      disposed = true;
    },
  });
  const response = new EventEmitter() as any;
  response.destroy = () => response.emit('close');
  const abort = new AbortController();
  const lease = forwardApplication(app, {} as any, response, abort.signal);
  abort.abort();
  await lease;
  await app.close();
  assert.equal(disposed, true);
  assert.equal(response.listenerCount('finish'), 0);
});

test('retired CredentialVault destroys its captured encryption key and cannot be reused', async () => {
  const { CredentialVault } = await import('../src/vault.js');
  const vault = new CredentialVault(Buffer.alloc(32, 1));
  const envelope = vault.seal('test', 'sensitive');
  vault.destroy();
  assert.throws(() => vault.open('test', envelope), /unavailable/i);
  assert.throws(() => vault.seal('test', 'new'), /unavailable/i);
});
