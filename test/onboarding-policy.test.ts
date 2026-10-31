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

test('tenant checklist never asks the operator to generate the shared platform setup key', () => {
  const guide = provisioningGuide('development', 'demo');
  assert.doesNotMatch(JSON.stringify(guide), /MANAGER_SETUP_CONTROL_KEY/);
  assert.equal(
    guide.proposedVariables.control,
    'WORKFLOW_REAL_DEMO_CONTROL_KEY',
  );
});

test('generated tenant environment snippet contains only tenant key variables', async () => {
  const { ProvisioningController } =
    await import('../src/onboarding/controller.js');
  const guide = provisioningGuide('development', 'demo');
  const controller = new ProvisioningController(
    { provisioning: async () => guide } as never,
    { keyFiles: async () => ({ files: [] }) } as never,
    {} as never,
    {
      keyStatus: async () => ({ available: false }),
      status: async () => ({
        configured: false,
        editable: false,
        available: false,
      }),
    } as never,
  );
  const result = await controller.get('development', 'demo');
  assert.equal(result.environmentSnippet.split('\n').length, 3);
  assert.doesNotMatch(result.environmentSnippet, /MANAGER_SETUP_CONTROL_KEY/);
  assert.match(
    result.environmentSnippet,
    /WORKFLOW_REAL_DEMO_WRAPPING_KEY_V1=/,
  );
});
