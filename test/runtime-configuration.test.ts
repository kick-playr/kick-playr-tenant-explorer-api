import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import {
  encodeRuntimeEnvelope,
  decodeRuntimeEnvelope,
} from '../src/runtime-configuration.js';
test('runtime envelope roundtrips private configuration and authenticates database and ciphertext', () => {
  const key = randomBytes(32),
    payload = {
      version: 2,
      tenants: [
        {
          id: 'demo',
          mongoUri:
            'mongodb://private:secret@cluster.invalid/demo?tls=true&authSource=admin',
        },
      ],
      other: { preserved: true },
    };
  const row = encodeRuntimeEnvelope(payload, key, 'control');
  assert.ok(!JSON.stringify(row).includes('private:secret'));
  assert.deepEqual(decodeRuntimeEnvelope(row, key, 'control'), payload);
  assert.throws(() => decodeRuntimeEnvelope(row, key, 'other'));
  assert.throws(() =>
    decodeRuntimeEnvelope(
      { ...row, ciphertext: Buffer.from('changed').toString('base64') },
      key,
      'control',
    ),
  );
  key.fill(0);
});
