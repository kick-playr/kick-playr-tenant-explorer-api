import { readFileSync, writeFileSync, chmodSync } from 'node:fs';
import { parseEnv } from 'node:util';
import { resolve } from 'node:path';

const args = process.argv.slice(2);
const expected = [
  '--bindings',
  '--explorer-env',
  '--runtime-env',
  '--runtime-config',
  '--control-config',
];
if (args.length !== 10 || expected.some((flag, i) => args[i * 2] !== flag))
  throw new Error(
    'Provide explicit bindings, explorer/runtime dotenv and private runtime/control config paths',
  );
const [
  bindingsFile,
  explorerEnvFile,
  runtimeEnvFile,
  runtimeFile,
  controlFile,
] = expected.map((_, i) => resolve(args[i * 2 + 1]));
const config = JSON.parse(readFileSync(bindingsFile, 'utf8'));
const explorerText = readFileSync(explorerEnvFile, 'utf8'),
  runtimeText = readFileSync(runtimeEnvFile, 'utf8');
const explorerEnv = parseEnv(explorerText),
  runtimeEnv = parseEnv(runtimeText);
const runtime = JSON.parse(readFileSync(runtimeFile, 'utf8')),
  control = JSON.parse(readFileSync(controlFile, 'utf8'));
if (
  config.version !== 1 ||
  !Array.isArray(config.bindings) ||
  config.bindings.length === 0
)
  throw new Error('Invalid key bindings');
const updates = {};
const migrated = config.bindings.map((binding) => {
  if (!/^[a-z0-9][a-z0-9-]*$/.test(binding.tenantId))
    throw new Error('Invalid tenant binding');
  const prefix = binding.tenantId.replaceAll('-', '_').toUpperCase();
  const variables = {
    wrapping: `${prefix}_WRAPPING_KEY_V1`,
    index: `${prefix}_INDEX_KEY`,
    control: `${prefix}_CONTROL_KEY`,
  };
  for (const kind of ['wrapping', 'index', 'control']) {
    let bytes;
    try {
      if (binding.files) bytes = readFileSync(binding.files[kind]);
      else {
        const value = explorerEnv[binding.variables[kind]];
        bytes = Buffer.from(value ?? '', 'base64');
        if (bytes.toString('base64') !== value)
          throw new Error('Invalid existing environment key');
      }
      if (bytes.length !== 32)
        throw new Error('Expected an existing 32-byte key');
      const value = bytes.toString('base64'),
        name = variables[kind];
      for (const env of [explorerEnv, runtimeEnv])
        if (env[name] !== undefined && env[name] !== value)
          throw new Error(`Refusing to replace a different existing ${name}`);
      if (updates[name] && updates[name] !== value)
        throw new Error('Conflicting tenant key binding');
      updates[name] = value;
    } finally {
      bytes?.fill(0);
    }
  }
  const row = runtime.tenants.find((row) => row.id === binding.tenantId);
  if (!row) throw new Error('Runtime tenant binding is missing');
  const controlField = `${binding.tenantId}ControlKeyFile`;
  if (typeof control[controlField] !== 'string')
    throw new Error('Control key binding is missing');
  const existingSources = {
    wrapping: row.wrappingKeyFile,
    index: row.indexKeyFile,
    control: control[controlField],
  };
  for (const kind of ['wrapping', 'index', 'control']) {
    let previous;
    try {
      const source = existingSources[kind];
      if (typeof source !== 'string')
        throw new Error('Invalid runtime key source');
      if (source.startsWith('env:')) {
        const value = runtimeEnv[source.slice(4)];
        previous = Buffer.from(value ?? '', 'base64');
        if (previous.toString('base64') !== value)
          throw new Error('Invalid runtime environment key');
      } else previous = readFileSync(source);
      if (
        previous.length !== 32 ||
        previous.toString('base64') !== updates[variables[kind]]
      )
        throw new Error(
          'Explorer and runtime key sources do not match; refusing migration',
        );
    } finally {
      previous?.fill(0);
    }
  }
  row.wrappingKeyFile = 'env:' + variables.wrapping;
  row.indexKeyFile = 'env:' + variables.index;
  control[controlField] = 'env:' + variables.control;
  const { files, variables: previousVariables, ...identity } = binding;
  void files;
  void previousVariables;
  return { ...identity, variables };
});
const next = { version: 1, bindings: migrated };
function update(text, entries) {
  let result = text;
  for (const [key, value] of Object.entries(entries)) {
    const pattern = new RegExp('^' + key + '=.*$', 'm');
    const line = key + '=' + value;
    result = pattern.test(result)
      ? result.replace(pattern, () => line)
      : result.trimEnd() + '\n' + line + '\n';
  }
  return result;
}
function save(path, text) {
  writeFileSync(path, text, { mode: 0o600 });
  chmodSync(path, 0o600);
}
save(runtimeEnvFile, update(runtimeText, updates));
save(
  explorerEnvFile,
  update(explorerText, {
    ...updates,
    EXPLORER_KEY_BINDINGS_JSON: "'" + JSON.stringify(next) + "'",
  }),
);
save(bindingsFile, JSON.stringify(next, null, 2) + '\n');
save(runtimeFile, JSON.stringify(runtime, null, 2) + '\n');
save(controlFile, JSON.stringify(control, null, 2) + '\n');
for (const path of [runtimeEnvFile, explorerEnvFile]) {
  const env = parseEnv(readFileSync(path, 'utf8'));
  for (const [name, value] of Object.entries(updates))
    if (env[name] !== value)
      throw new Error('Post-migration verification failed');
}
console.log(
  JSON.stringify({
    migratedKeys: Object.keys(updates),
    verifiedBytePreservation: true,
    originalFilesRetained: true,
  }),
);
