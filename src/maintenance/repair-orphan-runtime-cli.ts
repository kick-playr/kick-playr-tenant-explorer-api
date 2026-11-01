import { readFileSync } from 'node:fs';
import { mkdir, lstat, open, unlink } from 'node:fs/promises';
import { resolve, join, dirname } from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseEnv } from 'node:util';
import { randomUUID } from 'node:crypto';
import { MongoClient, type ClientSession } from 'mongodb';
import { createExplorerSecrets, type ExplorerSecrets } from '../secrets.js';
import type { RuntimeEnvelope } from '../runtime-configuration.js';
import { parseRepairArguments, repairOrphanRuntime, RepairError, type RepairStore } from './repair-orphan-runtime.js';

const help = `Usage: npm run repair:runtime -- --tenant <id> [--dry-run]
       npm run repair:runtime -- --tenant <id> --apply --expect-digest <dry-run-digest>

Development-only orphan repair. Dry-run is the default and performs no writes.
Removes the selected absent tenant's runtime/pending database references and
Explorer runtime/setup/key bindings from the encrypted shared configuration.
Any tenant definition, including deleted records, blocks repair.
Never deletes databases, tenant records, grants, vault secrets or keys.

Options:
  --env-file <path>    Explorer dotenv file; default .env in the current directory.
                      Exported variables take precedence. Existing vault mode is supported.
  --backup-dir <path>  Private encrypted backup directory; default .local/repair-backups.
  --dry-run           Explicit preview; cannot be combined with --apply.
  --apply             Requires the exact sourceDigest printed by dry-run.
  --help, -h          Print help without credentials or network access.

Apply saves an owner-only encrypted backup before using a MongoDB transaction
and exact-envelope compare-and-swap. A changed document requires another dry-run.
The existing shared key is reused. MongoDB must support transactions.
No services are started or restarted. Restart Explorer yourself after apply.
`;

export async function writeEncryptedBackup(directory: string, row: RuntimeEnvelope): Promise<string> {
  const folder = resolve(directory);
  const created = await mkdir(folder, { recursive: true, mode: 0o700 });
  const stat = await lstat(folder);
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0 || (process.getuid && stat.uid !== process.getuid())) throw new RepairError('UnsafeBackupDirectory');
  const path = join(folder, `runtime-development-${randomUUID()}.encrypted.json`);
  const file = await open(path, 'wx', 0o600);
  try { await file.writeFile(JSON.stringify(row) + '\n'); await file.sync(); }
  catch (error) { await file.close(); await unlink(path).catch(() => undefined); throw error; }
  await file.close();
  // Persist directory entries too: file fsync alone does not make a new backup
  // name (or newly created directory ancestry) durable across power loss.
  const stop = created ? dirname(resolve(created)) : folder;
  let current = folder;
  for (;;) {
    const directoryHandle = await open(current, 'r');
    try { await directoryHandle.sync(); } finally { await directoryHandle.close(); }
    if (current === stop) break;
    current = dirname(current);
  }
  return path;
}

async function main() {
  const args = parseRepairArguments(process.argv.slice(2));
  if (args.help) { process.stdout.write(help); return; }
  let fromFile: NodeJS.ProcessEnv = {};
  try { fromFile = parseEnv(readFileSync(resolve(args.envFile ?? '.env'), 'utf8')); }
  catch (error) { if (args.envFile || (error as NodeJS.ErrnoException).code !== 'ENOENT') throw new RepairError('EnvironmentFileUnavailable'); }
  const environment = { ...fromFile, ...process.env };
  environment.NODE_ENV ??= 'development';
  if (environment.NODE_ENV !== 'development' || environment.VERCEL !== undefined || environment.AWS_LAMBDA_FUNCTION_NAME !== undefined || (environment.VERCEL_ENV !== undefined && environment.VERCEL_ENV !== 'development') || (environment.LOCAL_KEYVAULT_ENVIRONMENT !== undefined && environment.LOCAL_KEYVAULT_ENVIRONMENT !== 'development')) throw new RepairError('DevelopmentOnly');
  const database = environment.EXPLORER_CONTROL_DATABASE;
  if (!database || !/^[A-Za-z0-9_-]{1,63}$/.test(database)) throw new RepairError('ControlDatabaseRequired');
  if (environment.SECRETS_KEYS_STRATEGY === 'LOCAL_KEYVAULT') {
    try {
      const auth: unknown = JSON.parse(environment.LOCAL_KEYVAULT_AUTH_JSON ?? '');
      if (!auth || typeof auth !== 'object' || !('schemaVersion' in auth) || auth.schemaVersion !== 1 || !('grants' in auth) || !Array.isArray(auth.grants)) throw Error();
    } catch { throw new RepairError('LocalVaultAuthInvalid'); }
  }
  let secrets: ExplorerSecrets | undefined, client: MongoClient | undefined, key: Buffer | undefined;
  try {
    // Only process bootstrap is loaded: tenant startup and Nest composition are never invoked.
    try { secrets = await createExplorerSecrets(environment); }
    catch { throw new RepairError('ProcessSecretsUnavailable'); }
    const values = secrets.environment;
    if (!values.EXPLORER_MONGODB_URI || !values.WORKFLOW_SHARED_WRAPPING_KEY_V1) throw new RepairError('BootstrapCredentialsRequired');
    key = Buffer.from(values.WORKFLOW_SHARED_WRAPPING_KEY_V1, 'base64');
    if (key.length !== 32 || key.toString('base64') !== values.WORKFLOW_SHARED_WRAPPING_KEY_V1) throw new RepairError('InvalidSharedKey');
    client = new MongoClient(values.EXPLORER_MONGODB_URI, { serverSelectionTimeoutMS: 5000, connectTimeoutMS: 5000, socketTimeoutMS: 5000, retryWrites: false });
    try { await client.connect(); }
    catch { throw new RepairError('ControlDatabaseConnectionFailed'); }
    const mongo = client;
    const collection = mongo.db(database).collection<RuntimeEnvelope>('tenantWorkflowConfiguration');
    const adapter = (session?: ClientSession): RepairStore => ({
      readEnvelope: () => collection.findOne({ _id: 'runtime:development' }, { session, maxTimeMS: 5000, readPreference: 'primary' }),
      hasTenantDefinition: async tenant => Boolean(await mongo.db(database).collection('tenantDefinitions').findOne({ id: tenant, environment: 'development' }, { session, projection: { _id: 1 }, maxTimeMS: 5000, readPreference: 'primary' })),
      compareAndSwap: async (original, next) => (await collection.replaceOne(original, next, { session, maxTimeMS: 5000 })).matchedCount === 1,
      transaction: async fn => {
        const tx = mongo.startSession();
        try { await tx.withTransaction(async () => { await fn(adapter(tx)); }, { readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority' }, readPreference: 'primary' }); }
        finally { await tx.endSession(); }
      },
    });
    const result = await repairOrphanRuntime(adapter(), key, { tenant: args.tenant!, database, apply: args.apply, expectedDigest: args.expectedDigest }, row => writeEncryptedBackup(args.backupDir ?? '.local/repair-backups', row));
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  } finally { key?.fill(0); secrets?.close(); await client?.close(); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  void main().catch(error => {
    const code = error instanceof RepairError ? error.code : 'RepairFailed';
    const hint = code === 'LocalVaultAuthInvalid'
      ? 'Set LOCAL_KEYVAULT_AUTH_JSON to valid JSON. In dotenv, quote the complete JSON value; use the grants script export output. Credential values are never shown.'
      : 'Check arguments, Explorer/vault configuration, connectivity and the reviewed dry-run. No raw error payload is logged.';
    process.stderr.write(`[runtime-repair] ${code}. ${hint}\n`);
    process.exitCode = 1;
  });
}
