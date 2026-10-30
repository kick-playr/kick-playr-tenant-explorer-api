import { BadRequestException } from '@nestjs/common';
import { z } from 'zod';

export const environments = [
  'development',
  'test',
  'preview',
  'production',
] as const;
export const statuses = [
  'provisioning',
  'active',
  'suspended',
  'disabled',
] as const;
export const providers = [
  'bexio',
  'matrix',
  'smtp',
  'dropbox',
  'pingen',
  'imap',
] as const;
export const identifier = z
  .string()
  .min(1)
  .max(64)
  .regex(/^[a-z0-9][a-z0-9-]*$/);
export const environmentSchema = z.enum(environments);
const text = z.string().trim().min(1).max(256);
const reference = z
  .string()
  .min(1)
  .max(512)
  .regex(/^[A-Za-z0-9][A-Za-z0-9/_:.-]*$/)
  .refine(
    (value) => !value.includes('://'),
    'Use an opaque secret reference, not a connection URI',
  );
export const revisionSchema = z.strictObject({
  expectedRevision: z
    .number()
    .int()
    .positive()
    .max(Number.MAX_SAFE_INTEGER - 1),
});
const realm = z
  .string()
  .max(256)
  .refine((value) => {
    try {
      const u = new URL(value);
      return (
        u.protocol === 'https:' &&
        u.origin === value &&
        !u.username &&
        !u.password
      );
    } catch {
      return false;
    }
  }, 'Identity realm must be an HTTPS issuer origin without a path');
const publicSchema = z.strictObject({
  name: text,
  locale: z
    .string()
    .min(2)
    .max(35)
    .refine((value) => {
      try {
        return Intl.getCanonicalLocales(value).length === 1;
      } catch {
        return false;
      }
    }, 'Invalid locale'),
});
const refs = z.strictObject({ mongoUri: reference, key: reference });
const hostname = z.string().min(1).max(259);
const configurationSchema = z
  .record(z.string(), z.json())
  .superRefine((value, ctx) => {
    if (Buffer.byteLength(JSON.stringify(value)) > 16384)
      ctx.addIssue({ code: 'custom', message: 'Configuration exceeds 16KB' });
    function visit(item: unknown, depth: number) {
      if (depth > 12) {
        ctx.addIssue({
          code: 'custom',
          message: 'Configuration is too deeply nested',
        });
        return;
      }
      if (item && typeof item === 'object')
        for (const [key, child] of Object.entries(item)) {
          if (
            key.startsWith('$') ||
            key.includes('.') ||
            ['__proto__', 'constructor', 'prototype'].includes(key)
          )
            ctx.addIssue({
              code: 'custom',
              message: 'Invalid configuration key',
            });
          if (
            /password|secret|token|credential|private.?key|api.?key|authorization/i.test(
              key,
            )
          )
            ctx.addIssue({
              code: 'custom',
              message: 'Store secrets in credentials, not configuration',
            });
          visit(child, depth + 1);
        }
    }
    visit(value, 0);
  });
const definitionFields = {
  hostname,
  aliases: z.array(hostname).max(32),
  public: publicSchema,
  secretReferences: refs,
};
export const createSchema = z.strictObject({
  id: identifier,
  environment: environmentSchema,
  ...definitionFields,
  identityRealm: realm,
});
export const updateSchema = z
  .strictObject({
    ...revisionSchema.shape,
    ...z.object(definitionFields).partial().shape,
    status: z.enum(statuses).optional(),
    identityRealm: realm.optional(),
    configuration: configurationSchema.optional(),
  })
  .refine((input) => Object.keys(input).length > 1, 'No changes supplied');
export const userSchema = z
  .strictObject({
    ...revisionSchema.shape,
    issuer: realm,
    subject: z
      .string()
      .min(1)
      .max(128)
      .regex(/^[A-Za-z0-9_-]+$/),
    contactId: z.number().int().positive(),
    permissions: z
      .array(
        z
          .string()
          .max(132)
          .regex(/^club:[a-z][a-z0-9:._-]{0,127}$/),
      )
      .max(128),
    status: z.enum(['active', 'disabled', 'revoked']),
  })
  .refine(
    (x) => new Set(x.permissions).size === x.permissions.length,
    'Duplicate permissions',
  );
export const integrationSchema = z.strictObject({
  ...revisionSchema.shape,
  provider: z.enum(providers),
  label: text,
  accountReference: text,
  capabilities: z
    .array(
      z
        .string()
        .min(1)
        .max(128)
        .regex(/^[a-z][a-z0-9:._-]*$/),
    )
    .max(64),
  credentialId: identifier,
  enabled: z.boolean(),
});
export const credentialSchema = z.strictObject({
  ...revisionSchema.shape,
  label: text,
  value: z.string().min(1).max(16384),
});
export const listSchema = z.strictObject({
  page: z.coerce.number().int().min(1).max(100000).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(20),
  search: z.string().trim().max(128).optional(),
  environment: environmentSchema.optional(),
  status: z.enum(statuses).optional(),
});
export function parse<T>(schema: z.ZodType<T>, value: unknown): T {
  const result = schema.safeParse(value);
  if (!result.success)
    throw new BadRequestException(
      result.error.issues
        .map((issue) => `${issue.path.join('.') || 'input'}: ${issue.message}`)
        .join('; '),
    );
  return result.data;
}
export function normalizeHost(value: string, environment: string): string {
  const match = /^([A-Za-z0-9.-]+)(?::([1-9][0-9]{0,4}))?$/.exec(value);
  if (!match)
    throw new BadRequestException(
      'Invalid tenant hostname; enter a hostname without a scheme or path',
    );
  const name = match[1]!.toLowerCase();
  if (
    name.length > 253 ||
    name
      .split('.')
      .some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))
  )
    throw new BadRequestException('Invalid tenant hostname');
  if (
    environment === 'production' &&
    (['kick-playr.ch', 'localhost', 'vercel.app'].includes(name) ||
      name.endsWith('.localhost') ||
      name.endsWith('.vercel.app'))
  )
    throw new BadRequestException('Reserved production hostname');
  if (
    match[2] &&
    (Number(match[2]) > 65535 ||
      environment !== 'development' ||
      !name.endsWith('.localhost'))
  )
    throw new BadRequestException(
      'Ports require a development .localhost hostname',
    );
  return name + (match[2] ? `:${match[2]}` : '');
}
export type ListQuery = z.infer<typeof listSchema>;
export interface Definition {
  id: string;
  environment: string;
  hostname: string;
  aliases: string[];
  status: (typeof statuses)[number];
  configRevision: number;
  public: { name: string; locale: string };
  secretReferences: { mongoUri: string; key: string };
}
export type TenantSummary = Definition;
export interface UserGrant {
  issuer: string;
  subject: string;
  revision: number;
  status: 'active' | 'revoked' | 'disabled';
  contactId: number;
  permissions: string[];
}
export interface Authority {
  schema: number;
  tenantId: string;
  environment: string;
  configRevision: number;
  authorityRevision: number;
  status: string;
  identityRealm: string;
  hostnames: string[];
  users: UserGrant[];
  services: unknown[];
  supportRevision?: number;
  [key: string]: unknown;
}
export interface Envelope {
  version: 1;
  nonce: string;
  ciphertext: string;
  tag: string;
}
export interface Credential {
  id: string;
  label: string;
  status: 'active' | 'revoked';
  revision: number;
  updatedAt: string;
  envelope?: Envelope;
}
export interface Integration {
  id: string;
  provider: (typeof providers)[number];
  label: string;
  accountReference: string;
  capabilities: string[];
  credentialId: string;
  enabled: boolean;
  updatedAt: string;
}
export interface Metadata {
  configuration: Record<string, unknown>;
  credentials: Credential[];
  integrations: Integration[];
}
export interface Aggregate {
  definition: Definition;
  authority: Authority | null;
  metadata: Metadata;
}
export interface AuditEvent {
  id: string;
  environment: string;
  tenantId: string;
  action: string;
  actor: string;
  revision: number;
  resource?: string;
  at: string;
}
export interface TenantView extends Definition {
  identityRealm: string;
  authorityRevision: number;
  configuration: Record<string, unknown>;
  users: UserGrant[];
  integrations: Integration[];
  credentials: Omit<Credential, 'envelope'>[];
}
export const emptyMetadata = (): Metadata => ({
  configuration: {},
  credentials: [],
  integrations: [],
});
