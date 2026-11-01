import { createHash, timingSafeEqual } from 'node:crypto';
import { decodeRuntimeEnvelope, encodeRuntimeEnvelope, type RuntimeEnvelope } from '../runtime-configuration.js';
import { envelopeDigest, RepairError } from './repair-orphan-runtime.js';

export interface MigrationDefinition { id: string; environment: string; configRevision: number; status: string; deletionId?: unknown }
export interface MigrationStore {
  readEnvelope(): Promise<RuntimeEnvelope | null>;
  readDefinition(tenant: string): Promise<MigrationDefinition | null>;
  compareAndSwap(original: RuntimeEnvelope, next: RuntimeEnvelope): Promise<boolean>;
  transaction(fn: (store: MigrationStore) => Promise<void>): Promise<void>;
}
export interface MigrationTargets {
  sharedScope: { environment: string; tenant: string };
  tenantScope: { environment: string; tenant: string };
  tenantRevision: number;
  tenantValues: { MONGODB_URI?: string; CLERK_SECRET_KEY?: string };
  sharedValues: { REDIS_URL?: string };
}
export interface MigrationOptions { tenant: string; database: string; apply?: boolean; expectedDigest?: string }
export interface MigrationCheck { field: string; target: string; status: 'will-reference' | 'already-referenced' | 'blocked'; reason?: string }
export interface MigrationPreview { mode: string; environment: string; tenant: string; database: string; sourceDigest: string; checks: MigrationCheck[]; readyToApply: boolean; applied: boolean; backupPath?: string }
function check(value: unknown, code: string): asserts value { if (!value) throw new RepairError(code); }
function record(value: unknown): Record<string, unknown> {
  check(value && typeof value === 'object' && !Array.isArray(value), 'InvalidRuntimeConfiguration');
  return value as Record<string, unknown>;
}
function definitionStamp(row: MigrationDefinition): string {
  return JSON.stringify([row.id, row.environment, row.configRevision, row.status, row.deletionId ?? null]);
}
function validDefinition(row: MigrationDefinition | null, tenant: string): asserts row is MigrationDefinition {
  check(row && row.id === tenant && row.environment === 'development' && Number.isSafeInteger(row.configRevision) && row.configRevision > 0 && !Object.hasOwn(row, 'deletionId') && ['active', 'disabled', 'provisioning'].includes(row.status), 'ActiveTenantDefinitionRequired');
}
function validUrl(value: string, protocols: string[]): boolean {
  try { const url = new URL(value); return protocols.includes(url.protocol) && !!url.hostname && value === value.trim() && !/[\x00-\x20\x7f]/.test(value); }
  catch { return false; }
}
function equal(a: string, b: string): boolean {
  return timingSafeEqual(createHash('sha256').update(a).digest(), createHash('sha256').update(b).digest());
}
export async function migrateRuntimeVault(store: MigrationStore, key: Buffer, options: MigrationOptions, loadTargets: (definition: MigrationDefinition) => Promise<MigrationTargets>, backup: (row: RuntimeEnvelope) => Promise<string>): Promise<MigrationPreview> {
  check(/^[a-z0-9][a-z0-9-]{0,63}$/.test(options.tenant), 'InvalidTenant');
  check(/^[A-Za-z0-9_-]{1,63}$/.test(options.database), 'InvalidDatabase');
  const definition = await store.readDefinition(options.tenant);
  validDefinition(definition, options.tenant);
  const original = await store.readEnvelope();
  check(original, 'RuntimeConfigurationMissing');
  const payload = decodeRuntimeEnvelope(original, key, options.database);
  check(payload.version === 2 && Array.isArray(payload.tenants), 'InvalidRuntimeConfiguration');
  const next = structuredClone(payload);
  const rows = (next.tenants as unknown[]).map(record);
  const selected = rows.filter(row => row.id === options.tenant);
  check(selected.length === 1, 'UniqueTenantRuntimeRequired');
  const tenant = selected[0]!;
  check((tenant.environment === undefined || tenant.environment === 'development') && (tenant.tenantId === undefined || tenant.tenantId === options.tenant), 'RuntimeScopeMismatch');
  const replay = record(next.replayConfig);
  const targets = await loadTargets(definition);
  check(targets.sharedScope.environment === 'development' && targets.sharedScope.tenant === '_shared' && targets.tenantScope.environment === 'development' && targets.tenantScope.tenant === options.tenant, 'VaultScopeMismatch');
  check(targets.tenantRevision === definition.configRevision, 'VaultTenantRevisionMismatch');
  const checks: MigrationCheck[] = [];
  function select(parent: Record<string, unknown>, field: string, path: string, mapping: string, value: string | undefined, valid: (value: string) => boolean) {
    const target = `vault:${mapping}`, source = parent[field];
    let reason: string | undefined;
    if (typeof value !== 'string' || !value) reason = 'VaultValueMissing';
    else if (!valid(value)) reason = 'InvalidVaultValue';
    else if (source === target) { checks.push({ field: path, target, status: 'already-referenced' }); return; }
    else if (typeof source !== 'string' || !source) reason = 'SourceValueMissing';
    else if (source.startsWith('vault:')) reason = 'ConflictingReference';
    else if (!equal(source, value)) reason = 'VaultValueMismatch';
    if (reason) checks.push({ field: path, target, status: 'blocked', reason });
    else { checks.push({ field: path, target, status: 'will-reference' }); parent[field] = target; }
  }
  select(tenant, 'mongoUri', `tenants.${options.tenant}.mongoUri`, 'MONGODB_URI', targets.tenantValues.MONGODB_URI, value => validUrl(value, ['mongodb:', 'mongodb+srv:']));
  select(tenant, 'clerkSecret', `tenants.${options.tenant}.clerkSecret`, 'CLERK_SECRET_KEY', targets.tenantValues.CLERK_SECRET_KEY, value => /^sk_(test|live)_[A-Za-z0-9_-]+$/.test(value));
  select(replay, 'url', 'replayConfig.url', 'REDIS_URL', targets.sharedValues.REDIS_URL, value => validUrl(value, ['redis:']));
  const sourceDigest = envelopeDigest(original);
  const preview: MigrationPreview = { mode: options.apply ? 'apply' : 'dry-run', environment: 'development', tenant: options.tenant, database: options.database, sourceDigest, checks, readyToApply: checks.every(c => c.status !== 'blocked'), applied: false };
  if (!options.apply || !preview.readyToApply || !checks.some(c => c.status === 'will-reference')) return preview;
  check(options.expectedDigest === sourceDigest, 'ConfigurationChanged');
  const backupPath = await backup(structuredClone(original));
  await store.transaction(async tx => {
    const currentDefinition = await tx.readDefinition(options.tenant);
    validDefinition(currentDefinition, options.tenant);
    check(definitionStamp(currentDefinition) === definitionStamp(definition), 'TenantDefinitionChanged');
    const current = await tx.readEnvelope();
    check(current && envelopeDigest(current) === sourceDigest, 'ConfigurationChanged');
    check(await tx.compareAndSwap(original, encodeRuntimeEnvelope(next, key, options.database)), 'ConfigurationChanged');
  });
  return { ...preview, applied: true, backupPath };
}
