import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseEnv } from 'node:util';
import { MongoClient, type ClientSession } from 'mongodb';
import { createSecretsRuntime, snapshotMappings, type SecretsRuntime } from '@kick-playr/local-key-vault/runtime-client';
import type { RuntimeEnvelope } from '../runtime-configuration.js';
import { parseRepairArguments, RepairError } from './repair-orphan-runtime.js';
import { writeEncryptedBackup } from './repair-orphan-runtime-cli.js';
import { migrateRuntimeVault, type MigrationDefinition, type MigrationStore } from './migrate-runtime-vault.js';

const help = `Usage: npm run migrate:runtime-vault -- --tenant fcrww --env-file <club-api.env>
       npm run migrate:runtime-vault -- --tenant fcrww --env-file <club-api.env> --apply --expect-digest <sourceDigest>

Dry-run by default. Replaces only the selected development tenant's mongoUri and
clerkSecret with vault:MONGODB_URI and vault:CLERK_SECRET_KEY, plus the shared
replayConfig.url with vault:REDIS_URL. The shared replay URL affects all tenants.
Reads the current club-api pinned snapshots and requires exact equality with the
old embedded values. Missing/invalid/different vault values block the entire write.
Does not import, generate, rotate or publish secrets. Does not start services.

Options: --tenant <id>, --env-file <path> (default .env), --dry-run,
--apply --expect-digest <reviewed digest>, --backup-dir <private path>, --help.
Apply saves an encrypted 0600 backup under .local/repair-backups before using a
transaction and exact-envelope compare-and-swap. Pausing concurrent provisioning
and maintenance is required. Restart consumers yourself after successful apply.
`;

async function main() {
  const args = parseRepairArguments(process.argv.slice(2));
  if (args.help) { process.stdout.write(help); return; }
  let fromFile: NodeJS.ProcessEnv = {};
  try { fromFile = parseEnv(readFileSync(resolve(args.envFile ?? '.env'), 'utf8')); }
  catch (error) { if (args.envFile || (error as NodeJS.ErrnoException).code !== 'ENOENT') throw new RepairError('EnvironmentFileUnavailable'); }
  const environment = { ...fromFile, ...process.env };
  environment.NODE_ENV ??= 'development';
  if (environment.NODE_ENV !== 'development' || environment.VERCEL !== undefined || environment.AWS_LAMBDA_FUNCTION_NAME !== undefined || (environment.VERCEL_ENV !== undefined && environment.VERCEL_ENV !== 'development') || (environment.LOCAL_KEYVAULT_ENVIRONMENT !== undefined && environment.LOCAL_KEYVAULT_ENVIRONMENT !== 'development')) throw new RepairError('DevelopmentOnly');
  if (environment.SECRETS_KEYS_STRATEGY !== 'LOCAL_KEYVAULT') throw new RepairError('LocalVaultStrategyRequired');
  let runtime: SecretsRuntime | undefined, client: MongoClient | undefined, key: Buffer | undefined;
  try {
    try { runtime = createSecretsRuntime({ environment }); } catch { throw new RepairError('LocalVaultAuthInvalid'); }
    const secrets = runtime;
    let application, loaded;
    try {
      application = await secrets.loadApplication('club-api');
      loaded = await secrets.loadProcess('club-api', { allowedMappings: application.request.secrets.map(s => s.mapping), requiredMappings: ['TENANT_CONTROL_MONGODB_URI', 'WORKFLOW_SHARED_WRAPPING_KEY_V1', 'REDIS_URL'] });
    } catch { throw new RepairError('PinnedProcessSnapshotUnavailable'); }
    if (application.scope.environment !== 'development' || application.scope.tenant !== '_shared') throw new RepairError('VaultScopeMismatch');
    const uri = loaded.mappings.TENANT_CONTROL_MONGODB_URI!;
    let database: string;
    try { const parsed = new URL(uri); database = decodeURIComponent(parsed.pathname.slice(1)); if (!['mongodb:', 'mongodb+srv:'].includes(parsed.protocol) || !/^[A-Za-z0-9_-]{1,63}$/.test(database)) throw Error(); }
    catch { throw new RepairError('InvalidControlDatabaseUri'); }
    const encoded = loaded.mappings.WORKFLOW_SHARED_WRAPPING_KEY_V1!;
    key = Buffer.from(encoded, 'base64');
    if (key.length !== 32 || key.toString('base64') !== encoded) throw new RepairError('InvalidSharedKey');
    client = new MongoClient(uri, { serverSelectionTimeoutMS: 5000, connectTimeoutMS: 5000, socketTimeoutMS: 5000, retryWrites: false });
    try { await client.connect(); } catch { throw new RepairError('ControlDatabaseConnectionFailed'); }
    const mongo = client, collection = mongo.db(database).collection<RuntimeEnvelope>('tenantWorkflowConfiguration');
    const adapter = (session?: ClientSession): MigrationStore => ({
      readEnvelope: () => collection.findOne({ _id: 'runtime:development' }, { session, maxTimeMS: 5000, readPreference: 'primary' }),
      readDefinition: tenant => mongo.db(database).collection<MigrationDefinition>('tenantDefinitions').findOne({ id: tenant, environment: 'development' }, { session, projection: { _id: 0, id: 1, environment: 1, configRevision: 1, status: 1, deletionId: 1 }, maxTimeMS: 5000, readPreference: 'primary' }),
      compareAndSwap: async (original, next) => (await collection.replaceOne(original, next, { session, maxTimeMS: 5000 })).matchedCount === 1,
      transaction: async fn => { const tx = mongo.startSession(); try { await tx.withTransaction(async () => { await fn(adapter(tx)); }, { readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority' }, readPreference: 'primary' }); } finally { await tx.endSession(); } },
    });
    const result = await migrateRuntimeVault(adapter(), key, { tenant: args.tenant!, database, apply: args.apply, expectedDigest: args.expectedDigest }, async definition => {
      let snapshot;
      try { snapshot = await secrets.loadTenant(definition.id, definition.configRevision); } catch { throw new RepairError('PinnedTenantSnapshotUnavailable'); }
      const values = snapshotMappings(snapshot);
      return { sharedScope: application.scope, tenantScope: { environment: snapshot.environment, tenant: snapshot.tenant }, tenantRevision: snapshot.bindingRevision, tenantValues: { MONGODB_URI: values.MONGODB_URI, CLERK_SECRET_KEY: values.CLERK_SECRET_KEY }, sharedValues: { REDIS_URL: loaded.mappings.REDIS_URL } };
    }, row => writeEncryptedBackup(args.backupDir ?? '.local/repair-backups', row));
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
    if (!result.readyToApply) process.exitCode = 1;
  } finally { key?.fill(0); runtime?.close(); await client?.close(); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  void main().catch(error => {
    const code = error instanceof RepairError ? error.code : 'MigrationFailed';
    process.stderr.write(`[runtime-vault-migration] ${code}. No raw credentials or error payloads are printed. Check the pinned snapshots and reviewed dry-run.\n`);
    process.exitCode = 1;
  });
}
