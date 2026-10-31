import test from 'node:test';
import assert from 'node:assert/strict';
import {
  referenceDefaults,
  provisioningGuide,
} from '../src/onboarding/policy.js';

test('reference names follow approved local, preview and production conventions', () => {
  for (const [environment, prefix] of [
    ['development', 'workflow-local'],
    ['preview', 'preview'],
    ['production', 'prod'],
  ]) {
    assert.deepEqual(referenceDefaults(environment!, 'fcrww'), {
      mongoUri: `${prefix}:fcrww:mongo`,
      key: `${prefix}:fcrww:key`,
    });
  }
  assert.throws(() => referenceDefaults('production', '../foreign'));
  assert.throws(() => referenceDefaults('unknown', 'fcrww'));
});
test('provisioning guide contains ordered manual installation and verification steps without secret values', () => {
  const guide = provisioningGuide('development', 'fcrww');
  assert.deepEqual(
    guide.steps.map((s) => s.id),
    ['clerk', 'claims', 'mongodb', 'keys', 'custody', 'email'],
  );
  assert.equal(guide.references.key, 'workflow-local:fcrww:key');
  assert.match(guide.steps.find((s) => s.id === 'claims')!.instructions, /aud/);
  assert.match(
    guide.steps.find((s) => s.id === 'custody')!.instructions,
    /HSM/,
  );
  assert.equal(guide.hsmSupported, false);
  assert.doesNotMatch(JSON.stringify(guide), /sk_test_|mongodb\+srv:\/\//);
});
