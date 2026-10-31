import { decodeRuntimeEnvelope } from './runtime-configuration.js';
import type { MongoClient } from 'mongodb';
import { z } from 'zod';
import { KeyFileRegistry, runtimeKeyBindings } from './key-files.js';
import { SetupRuntime } from './onboarding/runtime.js';
import { ClubRuntime, type RuntimeBinding } from './club-runtime.js';
import { trustedClubRealms, type PlatformAuthOptions } from './auth.js';

const fail = () => Error('Explorer database configuration unavailable');
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
/** Independent codec for the shared platform envelope; no sibling source imports. */
export async function loadExplorerConfiguration(
  client: Pick<MongoClient, 'db'>,
  database: string,
  key: Buffer,
): Promise<ExplorerDatabaseConfiguration> {
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
    const payload = decodeRuntimeEnvelope(row, key, database);
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
  }
}
