import test from 'node:test';
import assert from 'node:assert/strict';
import { keyBindingProof } from '../src/key-binding-proof.js';
test('key proof binds scope, variable, expiry and fresh challenge without exposing key material', () => {
  const key = Buffer.alloc(32, 4),
    binding = {
      environment: 'development',
      tenantId: 'demo',
      configRevision: 3,
      keyReference: 'workflow-local:demo:key',
      expiresAt: 31000,
    };
  const proof = keyBindingProof(
    key,
    binding,
    'a'.repeat(43),
    'index',
    'WORKFLOW_REAL_DEMO_INDEX_KEY',
  );
  assert.equal(proof, 'WUC0DDxy9IK8A5nFa9yLtMhJcWbodL6QAhMxK-DcNFE');
  assert.match(proof, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(
    proof,
    keyBindingProof(
      key,
      { ...binding, tenantId: 'other' },
      'a'.repeat(43),
      'index',
      'WORKFLOW_REAL_DEMO_INDEX_KEY',
    ),
  );
  assert.notEqual(
    proof,
    keyBindingProof(
      key,
      { ...binding, expiresAt: 32000 },
      'a'.repeat(43),
      'index',
      'WORKFLOW_REAL_DEMO_INDEX_KEY',
    ),
  );
  assert.notEqual(
    proof,
    keyBindingProof(
      key,
      binding,
      'b'.repeat(43),
      'index',
      'WORKFLOW_REAL_DEMO_INDEX_KEY',
    ),
  );
});
