import { createHash } from 'node:crypto';
import { decodeRuntimeEnvelope, encodeRuntimeEnvelope, type RuntimeEnvelope } from '../runtime-configuration.js';

export interface RepairStore {
  readEnvelope(): Promise<RuntimeEnvelope | null>;
  hasTenantDefinition(tenant: string): Promise<boolean>;
  compareAndSwap(original: RuntimeEnvelope, next: RuntimeEnvelope): Promise<boolean>;
  transaction(fn: (store: RepairStore) => Promise<void>): Promise<void>;
}
interface RepairOptions { tenant: string; database: string; apply?: boolean; expectedDigest?: string }
interface RepairArguments { help: boolean; apply: boolean; tenant?: string; expectedDigest?: string; envFile?: string; backupDir?: string }
export class RepairError extends Error {
  constructor(readonly code: string) { super(code); }
}
function check(value: unknown, code: string): asserts value {
  if (!value) throw new RepairError(code);
}
const tenantPattern = /^[a-z0-9][a-z0-9-]{0,63}$/;
const digestPattern = /^[a-f0-9]{64}$/;
export function parseRepairArguments(args: string[]): RepairArguments {
  if (args.length === 1 && ['--help', '-h'].includes(args[0]!)) return { help: true, apply: false };
  const result: RepairArguments = { help: false, apply: false };
  const seen = new Set<string>();
  for (let i = 0; i < args.length; i++) {
    const flag = args[i]!;
    check(!seen.has(flag), 'InvalidArguments'); seen.add(flag);
    if (flag === '--apply' || flag === '--dry-run') { result.apply = flag === '--apply'; continue; }
    check(['--tenant', '--expect-digest', '--env-file', '--backup-dir'].includes(flag), 'InvalidArguments');
    const value = args[++i];
    check(value && !value.startsWith('--'), 'InvalidArguments');
    if (flag === '--tenant') result.tenant = value;
    if (flag === '--expect-digest') result.expectedDigest = value;
    if (flag === '--env-file') result.envFile = value;
    if (flag === '--backup-dir') result.backupDir = value;
  }
  check(result.tenant && tenantPattern.test(result.tenant), 'InvalidTenant');
  check(!(seen.has('--apply') && seen.has('--dry-run')), 'InvalidArguments');
  check(result.expectedDigest === undefined || digestPattern.test(result.expectedDigest), 'InvalidDigest');
  check(!result.apply || result.expectedDigest, 'ApplyRequiresReviewedDigest');
  return result;
}
function record(value: unknown): Record<string, unknown> {
  check(value && typeof value === 'object' && !Array.isArray(value), 'InvalidRuntimeConfiguration');
  return value as Record<string, unknown>;
}
function prune(payload: Record<string, unknown>, tenant: string) {
  check(payload.version === 2, 'InvalidRuntimeConfiguration');
  const next = structuredClone(payload);
  const counts: Record<string, number> = {};
  function remove(parent: Record<string, unknown>, field: string, path: string, scoped: boolean) {
    const rows = parent[field];
    if (rows === undefined) return;
    check(Array.isArray(rows), 'InvalidRuntimeConfiguration');
    parent[field] = rows.filter(raw => {
      const row = record(raw);
      const id = scoped ? row.tenantId : row.id ?? row.tenantId;
      check(typeof id === 'string' && tenantPattern.test(id), 'InvalidRuntimeConfiguration');
      if (!scoped && row.id !== undefined && row.tenantId !== undefined) check(row.id === row.tenantId, 'InvalidRuntimeConfiguration');
      if (scoped) check(typeof row.environment === 'string', 'InvalidRuntimeConfiguration');
      const matches = id === tenant && (row.environment === undefined || row.environment === 'development');
      if (matches) counts[path] = (counts[path] ?? 0) + 1;
      return !matches;
    });
  }
  remove(next, 'tenants', 'tenants', false);
  remove(next, 'pendingMongoBindings', 'pendingMongoBindings', false);
  const explorer = record(next.explorer);
  for (const field of ['clubRuntimes', 'setupRuntimes']) remove(explorer, field, `explorer.${field}`, true);
  if (explorer.keyBindings !== undefined) remove(record(explorer.keyBindings), 'bindings', 'explorer.keyBindings.bindings', true);
  return { next, counts, total: Object.values(counts).reduce((sum, count) => sum + count, 0) };
}
export function envelopeDigest(row: RuntimeEnvelope): string {
  return createHash('sha256').update(JSON.stringify([row._id, row.version, row.nonce, row.ciphertext, row.tag])).digest('hex');
}
export async function repairOrphanRuntime(store: RepairStore, key: Buffer, options: RepairOptions, backup: (row: RuntimeEnvelope) => Promise<string>) {
  check(tenantPattern.test(options.tenant), 'InvalidTenant');
  check(/^[A-Za-z0-9_-]{1,63}$/.test(options.database), 'InvalidDatabase');
  check(!await store.hasTenantDefinition(options.tenant), 'TenantDefinitionExists');
  const original = await store.readEnvelope();
  check(original, 'RuntimeConfigurationMissing');
  const payload = decodeRuntimeEnvelope(original, key, options.database);
  const { next, counts, total } = prune(payload, options.tenant);
  const sourceDigest = envelopeDigest(original);
  const preview = { mode: options.apply ? 'apply' : 'dry-run', environment: 'development', tenant: options.tenant, database: options.database, sourceDigest, counts, total, applied: false };
  if (!options.apply || total === 0) return preview;
  check(options.expectedDigest === sourceDigest, 'ConfigurationChanged');
  // The backup contains the original authenticated ciphertext, never decoded values.
  const backupPath = await backup(structuredClone(original));
  await store.transaction(async tx => {
    check(!await tx.hasTenantDefinition(options.tenant), 'TenantDefinitionExists');
    const current = await tx.readEnvelope();
    check(current && envelopeDigest(current) === sourceDigest, 'ConfigurationChanged');
    const replacement = encodeRuntimeEnvelope(next, key, options.database);
    check(await tx.compareAndSwap(original, replacement), 'ConfigurationChanged');
  });
  return { ...preview, applied: true, backupPath };
}
