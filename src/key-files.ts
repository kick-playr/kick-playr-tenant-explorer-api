import { createHash } from 'node:crypto';
import { z } from 'zod';
import { environmentSchema, identifier } from './contracts.js';

const variableSchema = z
  .string()
  .max(128)
  .regex(
    /^(?!NEXT_PUBLIC_|VITE_|PUBLIC_)[A-Z][A-Z0-9_]*(?:WRAPPING_KEY_V[0-9]+|INDEX_KEY|CONTROL_KEY)$/,
  );
const identityFields = {
  tenantId: identifier,
  environment: environmentSchema,
  controlDatabase: z.string().min(1).max(63),
  keyReference: z.string().min(1).max(512),
  version: z.string().min(1).max(64),
  profile: z.string().min(1).max(64),
};
const bindingSchema = z.strictObject({
  ...identityFields,
  variables: z.strictObject({
    wrapping: variableSchema,
    index: variableSchema,
    control: variableSchema,
  }),
});
const configSchema = z.strictObject({
  version: z.literal(1),
  bindings: z.array(bindingSchema).max(256),
});
export type KeyBinding = z.infer<typeof bindingSchema>;
type KeyTenant = {
  id: string;
  environment: string;
  secretReferences: { key: string };
};
type FileStatus =
  'available' | 'missing' | 'insecure' | 'invalid' | 'unreadable';
interface KeyFileInfo {
  kind: 'wrapping' | 'index' | 'control';
  source?: 'file' | 'environment';
  filename?: string;
  path?: string;
  variable?: string;
  status: FileStatus;
  bytes?: number;
  fingerprint?: string;
}
export interface KeyFilesView {
  reference: string;
  status: 'connected' | 'unavailable' | 'unbound';
  profile?: string;
  version?: string;
  files: KeyFileInfo[];
}
/** Database-owned environment key references. Never reads configuration or key files. */
export class KeyFileRegistry {
  private readonly bindings: KeyBinding[];
  constructor(
    bindings: unknown = [],
    private readonly controlDatabase = '',
    private readonly environment: NodeJS.ProcessEnv = process.env,
    private readonly loadBindings?: () => Promise<KeyBinding[]>,
  ) {
    const parsed = configSchema.safeParse({ version: 1, bindings });
    if (!parsed.success) throw new Error('Invalid explorer key-file bindings');
    this.bindings = parsed.data.bindings;
    const identities = this.bindings.map((b) =>
      JSON.stringify([
        b.controlDatabase,
        b.environment,
        b.tenantId,
        b.keyReference,
      ]),
    );
    if (new Set(identities).size !== identities.length)
      throw new Error('Duplicate explorer key-file binding');
  }
  static async load(): Promise<never> {
    throw new Error(
      'Explorer bindings must be loaded from encrypted database configuration',
    );
  }
  async describe(tenant: KeyTenant): Promise<KeyFilesView> {
    if (this.loadBindings)
      return new KeyFileRegistry(
        await this.loadBindings(),
        this.controlDatabase,
        this.environment,
      ).describe(tenant);
    const reference = tenant.secretReferences.key;
    const binding = this.bindings.find(
      (b) =>
        b.controlDatabase === this.controlDatabase &&
        b.environment === tenant.environment &&
        b.tenantId === tenant.id &&
        b.keyReference === reference,
    );
    if (!binding) return { reference, status: 'unbound', files: [] };
    const files = await Promise.all(
      (['wrapping', 'index', 'control'] as const).map((kind) =>
        this.inspectVariable(kind, binding.variables[kind]),
      ),
    );
    return {
      reference,
      profile: binding.profile,
      version: binding.version,
      status: files.every((file) => file.status === 'available')
        ? 'connected'
        : 'unavailable',
      files,
    };
  }
  private inspectVariable(
    kind: KeyFileInfo['kind'],
    variable: string,
  ): KeyFileInfo {
    const info = { kind, source: 'environment' as const, variable };
    const value = this.environment[variable];
    if (value === undefined || value === '')
      return { ...info, status: 'missing' };
    let bytes: Buffer | undefined;
    try {
      if (value.length !== 44) return { ...info, status: 'invalid' };
      bytes = Buffer.from(value, 'base64');
      if (bytes.length !== 32 || bytes.toString('base64') !== value)
        return { ...info, status: 'invalid' };
      return {
        ...info,
        status: 'available',
        bytes: 32,
        fingerprint: createHash('sha256').update(bytes).digest('hex'),
      };
    } finally {
      bytes?.fill(0);
    }
  }
}

/** Derive display/verification metadata from the authenticated encrypted runtime
 * configuration. Environment-variable discovery never creates tenant bindings. */
export function runtimeKeyBindings(
  payload: unknown,
  database: string,
  explicit: unknown[],
): KeyBinding[] {
  const existing = configSchema.parse({
    version: 1,
    bindings: explicit,
  }).bindings;
  const manifest = payload as { profile?: unknown; tenants?: unknown };
  // Compatibility for explorer-only envelopes that predate runtime metadata.
  if (manifest.tenants === undefined) return existing;
  if (
    !['workflow-real', 'workflow-local'].includes(manifest.profile as string) ||
    !Array.isArray(manifest.tenants) ||
    manifest.tenants.length > 32
  )
    throw new Error('Invalid runtime key bindings');
  const seen = new Set<string>();
  for (const row of manifest.tenants) {
    const tenantId = identifier.parse(row?.id);
    if (seen.has(tenantId)) throw new Error('Duplicate runtime tenant binding');
    seen.add(tenantId);
    const variable = (ref: unknown, suffix: string) => {
      if (
        typeof ref !== 'string' ||
        !ref.startsWith('env:') ||
        !ref.endsWith(suffix)
      )
        throw new Error('Invalid runtime key reference');
      return variableSchema.parse(ref.slice(4));
    };
    const binding = bindingSchema.parse({
      tenantId,
      environment: 'development',
      controlDatabase: database,
      keyReference: `workflow-local:${tenantId}:key`,
      version: 'v1',
      profile: manifest.profile,
      variables: {
        wrapping: variable(row.wrappingKeyRef, 'WRAPPING_KEY_V1'),
        index: variable(row.indexKeyRef, 'INDEX_KEY'),
        control: variable(row.controlKeyRef, 'CONTROL_KEY'),
      },
    });
    const prior = existing.find(
      (b) =>
        b.tenantId === tenantId &&
        b.environment === 'development' &&
        b.controlDatabase === database &&
        b.keyReference === binding.keyReference,
    );
    if (prior) {
      if (
        (['wrapping', 'index', 'control'] as const).some(
          (kind) => prior.variables[kind] !== binding.variables[kind],
        )
      )
        throw new Error('Conflicting runtime key bindings');
      existing.splice(existing.indexOf(prior), 1, binding);
    } else existing.push(binding);
  }
  return existing;
}
