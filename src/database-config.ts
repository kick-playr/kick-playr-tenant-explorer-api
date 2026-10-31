import { createDecipheriv } from 'node:crypto';
import type { MongoClient } from 'mongodb';
import { z } from 'zod';
import { KeyFileRegistry, runtimeKeyBindings } from './key-files.js';
import { SetupRuntime } from './onboarding/runtime.js';
import { ClubRuntime, type RuntimeBinding } from './club-runtime.js';
import { trustedClubRealms, type PlatformAuthOptions } from './auth.js';

const fail = () => Error('Explorer database configuration unavailable');
const MAX_BYTES = 2 * 1024 * 1024;
export function validRealmHost(value: unknown): value is string {
  if (
    typeof value !== 'string' ||
    value.length > 253 ||
    !/^[a-z0-9][a-z0-9.-]*(?::[1-9][0-9]{0,4})?$/.test(value)
  )
    return false;
  try {
    const url = new URL('http://' + value);
    return (
      url.host === value &&
      !url.username &&
      !url.password &&
      url.pathname === '/'
    );
  } catch {
    return false;
  }
}
const hostSchema = z.string().refine(validRealmHost);
const frontendHostSchema = z.strictObject({
  publishableKey: z
    .string()
    .regex(/^pk_(?:test|live)_[A-Za-z0-9+/_=-]+$/)
    .max(4096),
  secretVariable: z
    .string()
    .regex(/^EXPLORER_CLUB_[A-Z0-9_]+_CLERK_SECRET_KEY$/)
    .max(128),
});
const explorerSchema = z.strictObject({
  issuer: z
    .string()
    .url()
    .refine((value) => {
      const url = new URL(value);
      return (
        url.protocol === 'https:' &&
        url.origin === value &&
        !url.username &&
        !url.password
      );
    }),
  authorizedParties: z
    .array(
      z
        .string()
        .url()
        .refine((value) => {
          const url = new URL(value);
          return (
            url.origin === value &&
            !url.username &&
            !url.password &&
            (url.protocol === 'https:' ||
              (url.protocol === 'http:' &&
                (['localhost', '127.0.0.1', '[::1]'].includes(url.hostname) ||
                  url.hostname.endsWith('.localhost'))))
          );
        }),
    )
    .min(1)
    .max(100),
  adminSubjects: z
    .array(z.string().regex(/^[A-Za-z0-9_-]{1,128}$/))
    .min(1)
    .max(256),
  keyBindings: z.strictObject({
    version: z.literal(1),
    bindings: z.array(z.unknown()).max(256),
  }),
  clubRuntimes: z.array(z.unknown()).max(100),
  setupRuntimes: z.array(z.unknown()).max(100).optional(),
  clubRealms: z.array(z.unknown()).max(100),
  frontendHosts: z
    .record(hostSchema, frontendHostSchema)
    .refine((value) => Object.keys(value).length <= 100),
  platformHosts: z.array(hostSchema).max(100),
});
export interface ExplorerDatabaseConfiguration {
  issuer: string;
  authorizedParties: string[];
  adminSubjects: string[];
  keyBindings: { version: 1; bindings: unknown[] };
  clubRuntimes: RuntimeBinding[];
  setupRuntimes?: {environment:string;tenantId:string;origin:string}[];
  clubRealms: NonNullable<PlatformAuthOptions['clubRealms']>;
  frontendHosts: Record<
    string,
    { publishableKey: string; secretVariable: string }
  >;
  platformHosts: string[];
}
function base64(value: unknown, max: number): Buffer {
  if (
    typeof value !== 'string' ||
    !value ||
    value.length > Math.ceil(max / 3) * 4
  )
    throw fail();
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length > max || bytes.toString('base64') !== value) throw fail();
  return bytes;
}
/** Independent codec for the shared platform envelope; no sibling source imports. */
export async function loadExplorerConfiguration(
  client: Pick<MongoClient, 'db'>,
  database: string,
  key: Buffer,
): Promise<ExplorerDatabaseConfiguration> {
  let plain: Buffer | undefined;
  try {
    if (
      !Buffer.isBuffer(key) ||
      key.length !== 32 ||
      typeof database !== 'string' ||
      !/^[A-Za-z0-9_-]{1,63}$/.test(database)
    )
      throw fail();
    const row = await client
      .db(database)
      .collection<{
        _id: string;
        version: unknown;
        nonce: unknown;
        tag: unknown;
        ciphertext: unknown;
      }>('tenantWorkflowConfiguration')
      .findOne({ _id: 'runtime:development' } as any, {
        readPreference: 'primary',
        maxTimeMS: 5000,
      });
    if (
      !row ||
      Object.keys(row).sort().join() !== '_id,ciphertext,nonce,tag,version' ||
      row._id !== 'runtime:development' ||
      row.version !== 1
    )
      throw fail();
    const nonce = base64(row.nonce, 12),
      tag = base64(row.tag, 16),
      ciphertext = base64(row.ciphertext, MAX_BYTES);
    if (nonce.length !== 12 || tag.length !== 16) throw fail();
    const decipher = createDecipheriv('aes-256-gcm', key, nonce, {
      authTagLength: 16,
    });
    decipher.setAAD(
      Buffer.from(
        JSON.stringify([
          'kick-playr:tenant-workflow-configuration',
          database,
          1,
        ]),
      ),
    );
    decipher.setAuthTag(tag);
    plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    if (plain.length > MAX_BYTES) throw fail();
    const payload: unknown = JSON.parse(plain.toString('utf8'));
    if (
      !payload ||
      typeof payload !== 'object' ||
      Array.isArray(payload) ||
      !('version' in payload) ||
      payload.version !== 2 ||
      !('explorer' in payload)
    )
      throw fail();
    const config = explorerSchema.parse(payload.explorer);
    config.keyBindings.bindings = runtimeKeyBindings(payload, database, config.keyBindings.bindings);
    // These constructors preserve the existing tenant key-reference, destination,
    // origin and issuer checks before any application services are constructed.
    new KeyFileRegistry(config.keyBindings.bindings, database);
    new ClubRuntime(config.clubRuntimes);
    if(config.setupRuntimes)new SetupRuntime(config.setupRuntimes);
    const realms = trustedClubRealms(config.clubRealms, config.issuer);
    if (
      new Set(config.platformHosts).size !== config.platformHosts.length ||
      config.platformHosts.some((host) =>
        Object.hasOwn(config.frontendHosts, host),
      )
    )
      throw fail();
    return structuredClone({
      ...config,
      clubRealms: realms,
    }) as ExplorerDatabaseConfiguration;
  } catch {
    throw fail();
  } finally {
    plain?.fill(0);
  }
}
