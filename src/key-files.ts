import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import { basename, isAbsolute } from 'node:path';
import { createHash } from 'node:crypto';
import { z } from 'zod';
import { environmentSchema, identifier } from './contracts.js';

const pathSchema = z.string().min(1).max(4096).refine(isAbsolute);
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
const bindingSchema = z.union([
  z.strictObject({
    ...identityFields,
    files: z.strictObject({
      wrapping: pathSchema,
      index: pathSchema,
      control: pathSchema,
    }),
  }),
  z.strictObject({
    ...identityFields,
    variables: z.strictObject({
      wrapping: variableSchema,
      index: variableSchema,
      control: variableSchema,
    }),
  }),
]);
const configSchema = z.strictObject({
  version: z.literal(1),
  bindings: z.array(bindingSchema).max(256),
});
type KeyBinding = z.infer<typeof bindingSchema>;
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
function privateMode(stat: {
  mode: number;
  uid: number;
  nlink: number;
  isFile(): boolean;
}) {
  return (
    stat.isFile() &&
    stat.nlink === 1 &&
    (process.platform === 'win32' ||
      ((stat.mode & 0o077) === 0 && stat.uid === process.getuid?.()))
  );
}

/** Explicit server-owned paths only. HTTP inputs can select a tenant, never a file. */
export class KeyFileRegistry {
  private readonly bindings: KeyBinding[];
  constructor(
    bindings: unknown = [],
    private readonly controlDatabase = '',
    private readonly environment: NodeJS.ProcessEnv = process.env,
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
  static async load(
    path: string | undefined,
    database: string,
    env: NodeJS.ProcessEnv = process.env,
  ): Promise<KeyFileRegistry> {
    if (env.EXPLORER_KEY_BINDINGS_JSON) {
      try {
        const text = env.EXPLORER_KEY_BINDINGS_JSON;
        if (Buffer.byteLength(text) > 131072) throw new Error();
        const config = configSchema.parse(JSON.parse(text));
        return new KeyFileRegistry(config.bindings, database, env);
      } catch {
        throw new Error(
          'Explorer key environment bindings are unavailable or invalid',
        );
      }
    }
    if (!path) return new KeyFileRegistry([], database, env);
    let file;
    try {
      if (!isAbsolute(path)) throw new Error();
      file = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
      const stat = await file.stat();
      if (!privateMode(stat) || stat.size > 131072) throw new Error();
      const parsed = configSchema.safeParse(
        JSON.parse(await file.readFile('utf8')),
      );
      if (!parsed.success) throw new Error();
      return new KeyFileRegistry(parsed.data.bindings, database, env);
    } catch {
      throw new Error('Explorer key-file bindings are unavailable or invalid');
    } finally {
      await file?.close();
    }
  }
  async describe(tenant: KeyTenant): Promise<KeyFilesView> {
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
        'variables' in binding
          ? this.inspectVariable(kind, binding.variables[kind])
          : this.inspect(kind, binding.files[kind]),
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
  private async inspect(
    kind: KeyFileInfo['kind'],
    path: string,
  ): Promise<KeyFileInfo> {
    const info = {
      kind,
      source: 'file' as const,
      path,
      filename: basename(path),
    };
    let file;
    const bytes = Buffer.alloc(33);
    try {
      file = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
      const stat = await file.stat();
      if (!privateMode(stat)) return { ...info, status: 'insecure' };
      if (stat.size !== 32) return { ...info, status: 'invalid' };
      const read = await file.read(bytes, 0, 33, 0);
      if (read.bytesRead !== 32) return { ...info, status: 'invalid' };
      return {
        ...info,
        status: 'available',
        bytes: 32,
        fingerprint: createHash('sha256')
          .update(bytes.subarray(0, 32))
          .digest('hex'),
      };
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      return {
        ...info,
        status:
          code === 'ENOENT'
            ? 'missing'
            : code === 'ELOOP'
              ? 'insecure'
              : 'unreadable',
      };
    } finally {
      bytes.fill(0);
      await file?.close();
    }
  }
}
