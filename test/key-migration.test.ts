import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { parseEnv } from 'node:util';

test('migration refuses a binding that differs from the runtime key before writing dotenv', () => {
  const dir = mkdtempSync(join(tmpdir(), 'key-migration-'));
  try {
    const file = (name: string, value: string | Buffer) => {
      const path = join(dir, name);
      writeFileSync(path, value, { mode: 0o600 });
      return path;
    };
    const paths = {
      wrapping: file('wrap.key', Buffer.alloc(32, 1)),
      index: file('index.key', Buffer.alloc(32, 2)),
      control: file('control.key', Buffer.alloc(32, 3)),
    };
    const foreign = file('wrong.key', Buffer.alloc(32, 9));
    const bindings = file(
      'bindings.json',
      JSON.stringify({
        version: 1,
        bindings: [
          {
            tenantId: 'fcrww',
            environment: 'development',
            controlDatabase: 'control',
            keyReference: 'real-development:fcrww:key',
            version: 'v1',
            profile: 'real-development',
            files: paths,
          },
        ],
      }),
    );
    const explorerEnv = file('explorer.env', 'PORT=3003\n'),
      runtimeEnv = file('runtime.env', 'NODE_ENV=development\n');
    const runtime = file(
      'runtime.json',
      JSON.stringify({
        tenants: [
          { id: 'fcrww', wrappingKeyFile: foreign, indexKeyFile: paths.index },
        ],
      }),
    );
    const control = file(
      'control.json',
      JSON.stringify({ fcrwwControlKeyFile: paths.control }),
    );
    const result = spawnSync(
      process.execPath,
      [
        resolve('scripts/migrate-key-environment.mjs'),
        '--bindings',
        bindings,
        '--explorer-env',
        explorerEnv,
        '--runtime-env',
        runtimeEnv,
        '--runtime-config',
        runtime,
        '--control-config',
        control,
      ],
      { encoding: 'utf8' },
    );
    assert.notEqual(result.status, 0);
    assert.equal(
      parseEnv(readFileSync(explorerEnv, 'utf8')).FCRWW_WRAPPING_KEY_V1,
      undefined,
    );
    assert.equal(readFileSync(runtimeEnv, 'utf8'), 'NODE_ENV=development\n');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
