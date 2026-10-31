import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { createHash, randomUUID } from 'node:crypto';
import type { MongoClient } from 'mongodb';
import { ConnectionString } from 'mongodb-connection-string-url';
import { z } from 'zod';
import { environmentSchema, identifier, parse } from './contracts.js';
import {
  encodeRuntimeEnvelope,
  decodeRuntimeEnvelope,
  type RuntimeEnvelope,
} from './runtime-configuration.js';
import type { Scope } from './invitations/types.js';
const draftSchema = z
  .array(
    z.strictObject({
      tenantId: identifier,
      mongoUri: z.string().min(1).max(8192),
    }),
  )
  .max(32);
const inputSchema = z.strictObject({
  uri: z.string().min(1).max(8192),
  expectedRevision: z.string().regex(/^[a-f0-9]{64}$/),
});
const unavailable = () =>
  new ServiceUnavailableException('MongoDB configuration storage unavailable');
const conflict = () =>
  new ConflictException('Configuration changed. Reload before saving.');
const positive = (v: unknown): v is number =>
  Number.isSafeInteger(v) &&
  Number(v) > 0 &&
  Number(v) < Number.MAX_SAFE_INTEGER - 1;
export interface MongoConfigurationStatus {
  configured: boolean;
  editable: boolean;
  available: boolean;
  revision: string | null;
  source: 'runtime' | 'pending' | null;
  requiresReload: boolean;
  onboardingRevision?: number;
}
function cluster(uri: string) {
  const parsed = new ConnectionString(uri);
  const options = new Map<string, string>();
  for (const [k, v] of parsed.searchParams) {
    const name = k.toLowerCase();
    if (options.has(name)) throw Error();
    options.set(name, v);
  }
  const allowed = [
    'tls',
    'ssl',
    'authsource',
    'authmechanism',
    'replicaset',
    'directconnection',
    'compressors',
    'srvservicename',
    'srvmaxhosts',
  ];
  if (
    parsed.hash ||
    !parsed.username ||
    !parsed.password ||
    !options.get('authsource') ||
    [...options.keys()].some((k) => !allowed.includes(k)) ||
    (options.has('tls') && options.has('ssl'))
  )
    throw Error();
  const tls = options.get('tls') ?? options.get('ssl');
  if (tls === undefined ? parsed.protocol !== 'mongodb+srv:' : tls !== 'true')
    throw Error();
  if (
    /[\x00-\x20\x7f]/.test(decodeURIComponent(parsed.username)) ||
    /[\x00-\x20\x7f]/.test(decodeURIComponent(parsed.password))
  )
    throw Error();
  return {
    database: decodeURIComponent(parsed.pathname.slice(1)),
    fingerprint: createHash('sha256')
      .update(
        JSON.stringify({
          protocol: parsed.protocol,
          hosts: parsed.hosts.map((h) => h.toLowerCase()).sort(),
          username: decodeURIComponent(parsed.username),
          password: decodeURIComponent(parsed.password),
          options: [...options].sort(([a], [b]) => a.localeCompare(b)),
        }),
      )
      .digest('hex'),
  };
}
/** Server-only writer; never connects to a URL supplied by the browser. */
export class RuntimeMongoService {
  private closed = false;
  constructor(
    private readonly client: MongoClient,
    private readonly database: string,
    private readonly key: Buffer,
    private readonly controlUri: string,
  ) {
    if (key.length !== 32 || !/^[A-Za-z0-9_-]{1,63}$/.test(database))
      throw unavailable();
  }
  onModuleDestroy() {
    this.closed = true;
    this.key.fill(0);
  }
  private scope(s: Scope) {
    parse(
      z.strictObject({ environment: environmentSchema, tenantId: identifier }),
      s,
    );
  }
  private active() {
    if (this.closed) throw unavailable();
  }
  private collection(name: string) {
    return this.client.db(this.database).collection(name);
  }
  private revision(row: RuntimeEnvelope) {
    return createHash('sha256').update(JSON.stringify(row)).digest('hex');
  }
  private async root(opts: Record<string, unknown>) {
    this.active();
    const row = await this.client
      .db(this.database)
      .collection<RuntimeEnvelope>('tenantWorkflowConfiguration')
      .findOne({ _id: 'runtime:development' }, opts);
    let payload: Record<string, unknown>;
    try {
      payload = decodeRuntimeEnvelope(row, this.key, this.database);
    } catch {
      throw unavailable();
    }
    if (
      payload.version !== 2 ||
      !['workflow-real', 'workflow-local'].includes(String(payload.profile)) ||
      !Array.isArray(payload.tenants) ||
      payload.tenants.length > 32 ||
      !row
    )
      throw unavailable();
    const tenants = payload.tenants as Record<string, unknown>[];
    if (
      tenants.some((t) => !t || !identifier.safeParse(t.id).success) ||
      new Set(tenants.map((t) => t.id)).size !== tenants.length
    )
      throw unavailable();
    const pending = draftSchema.safeParse(payload.pendingMongoBindings ?? []);
    if (
      !pending.success ||
      new Set(pending.data.map((t) => t.tenantId)).size !== pending.data.length
    )
      throw unavailable();
    return { row, payload, tenants, pending: pending.data };
  }
  private async tenant(s: Scope, opts: Record<string, unknown>) {
    const definition = await this.collection('tenantDefinitions').findOne(
      { id: s.tenantId, environment: s.environment },
      opts,
    );
    if (!definition) throw new NotFoundException('Tenant not found');
    const authority = await this.collection('tenantRuntimeAuthorities').findOne(
      { tenantId: s.tenantId, environment: s.environment },
      opts,
    );
    const invitations = await this.collection(
      'tenantManagerInvitations',
    ).findOne({ _id: `${s.environment}/${s.tenantId}` as never }, opts);
    const editable =
      definition.status === 'provisioning' &&
      positive(definition.configRevision) &&
      definition.secretReferences?.mongoUri ===
        `workflow-local:${s.tenantId}:mongo` &&
      authority?.schema === 1 &&
      authority.status === 'disabled' &&
      authority.configRevision === definition.configRevision &&
      positive(authority.authorityRevision) &&
      positive(authority.supportRevision) &&
      Array.isArray(authority.users) &&
      !authority.users.length &&
      Array.isArray(authority.services) &&
      !authority.services.length &&
      (!invitations ||
        (Array.isArray(invitations.invitations) &&
          !invitations.invitations.length &&
          Array.isArray(invitations.principals) &&
          !invitations.principals.length &&
          !invitations.owner &&
          !invitations.bootstrapInvitationId &&
          !invitations.onboarding?.ownerCompletedAt &&
          Number.isSafeInteger(invitations.revision) &&
          invitations.revision >= 0 &&
          invitations.revision < Number.MAX_SAFE_INTEGER - 1));
    return { definition, authority, invitations, editable: Boolean(editable) };
  }
  async status(s: Scope): Promise<MongoConfigurationStatus> {
    this.scope(s);
    this.active();
    if (s.environment !== 'development')
      return {
        configured: false,
        editable: false,
        available: false,
        revision: null,
        source: null,
        requiresReload: false,
      };
    const opts = { maxTimeMS: 3000 };
    const root = await this.root(opts),
      tenant = await this.tenant(s, opts);
    const source = root.tenants.some(
      (t) =>
        t.id === s.tenantId &&
        typeof t.mongoUri === 'string' &&
        t.mongoUri.length,
    )
      ? 'runtime'
      : root.pending.some((t) => t.tenantId === s.tenantId)
        ? 'pending'
        : null;
    return {
      configured: source !== null,
      editable: tenant.editable,
      available: true,
      revision: this.revision(root.row),
      source,
      requiresReload: source !== null,
      onboardingRevision: tenant.invitations?.revision ?? 0,
    };
  }
  async save(
    s: Scope,
    body: unknown,
    actor: { subject: string | undefined; expiresAt: number | undefined },
  ): Promise<MongoConfigurationStatus> {
    this.scope(s);
    this.active();
    const input = parse(inputSchema, body);
    if (s.environment !== 'development')
      throw new BadRequestException(
        'MongoDB configuration adapter is unavailable for this environment',
      );
    const live = () => {
      this.active();
      if (
        !actor.subject ||
        !Number.isFinite(actor.expiresAt) ||
        actor.expiresAt! <= Date.now()
      )
        throw new ForbiddenException('Platform authorization expired');
    };
    live();
    const session = this.client.startSession();
    try {
      return await session.withTransaction(
        async () => {
          live();
          const opts = { session, maxTimeMS: 3000 },
            root = await this.root(opts),
            tenant = await this.tenant(s, opts);
          if (!tenant.editable)
            throw new ConflictException(
              'MongoDB URL can only be configured before the first manager invitation',
            );
          if (this.revision(root.row) !== input.expectedRevision)
            throw conflict();
          const existing = root.tenants.find((t) => t.id === s.tenantId);
          const baseline =
            root.tenants.find((t) => typeof t.mongoUri === 'string')
              ?.mongoUri ?? this.controlUri;
          try {
            if (
              input.uri !== input.uri.trim() ||
              /[\x00-\x20\x7f]/.test(input.uri)
            )
              throw Error();
            const target = cluster(input.uri),
              expected = cluster(String(baseline));
            if (
              target.fingerprint !== expected.fingerprint ||
              !/^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$/.test(target.database) ||
              [
                'admin',
                'local',
                'config',
                this.database.toLowerCase(),
              ].includes(target.database.toLowerCase())
            )
              throw Error();
            const others = [
              ...root.tenants.filter((t) => t.id !== s.tenantId),
              ...root.pending.filter((t) => t.tenantId !== s.tenantId),
            ];
            if (
              others.some(
                (t) =>
                  cluster(String(t.mongoUri)).database.toLowerCase() ===
                  target.database.toLowerCase(),
              )
            )
              throw Error();
          } catch {
            throw new BadRequestException(
              'Use a distinct tenant database on the configured TLS runtime cluster with its configured credentials and authSource',
            );
          }
          const fence = await this.collection('tenantDefinitions').updateOne(
            {
              id: s.tenantId,
              environment: s.environment,
              status: 'provisioning',
              configRevision: tenant.definition.configRevision,
            },
            { $inc: { invitationFence: 1 } },
            opts,
          );
          if (fence.matchedCount !== 1) throw conflict();
          const authorityFence = await this.collection(
            'tenantRuntimeAuthorities',
          ).updateOne(
            {
              tenantId: s.tenantId,
              environment: s.environment,
              status: 'disabled',
              authorityRevision: tenant.authority!.authorityRevision,
            },
            { $inc: { authorityRevision: 1, supportRevision: 1 } },
            opts,
          );
          if (authorityFence.matchedCount !== 1) throw conflict();
          const pending = root.pending.filter((t) => t.tenantId !== s.tenantId);
          if (existing) existing.mongoUri = input.uri;
          else pending.push({ tenantId: s.tenantId, mongoUri: input.uri });
          if (pending.length > 32)
            throw new BadRequestException('Provisioning draft limit reached');
          if (pending.length) root.payload.pendingMongoBindings = pending;
          else delete root.payload.pendingMongoBindings;
          const sealed = encodeRuntimeEnvelope(
            root.payload,
            this.key,
            this.database,
          );
          const changed = await this.client
            .db(this.database)
            .collection<RuntimeEnvelope>('tenantWorkflowConfiguration')
            .replaceOne(root.row, sealed, opts);
          if (changed.matchedCount !== 1) throw conflict();
          const state = tenant.invitations
            ? structuredClone(tenant.invitations)
            : ({
                _id: `${s.environment}/${s.tenantId}`,
                revision: 0,
                invitations: [],
                principals: [],
              } as Record<string, any>);
          if (state.onboarding) delete state.onboarding.provisioning;
          state.revision++;
          if (tenant.invitations) {
            const saved = await this.collection(
              'tenantManagerInvitations',
            ).replaceOne(
              {
                _id: `${s.environment}/${s.tenantId}` as never,
                revision: tenant.invitations.revision,
              },
              state,
              opts,
            );
            if (saved.matchedCount !== 1) throw conflict();
          } else
            await this.collection('tenantManagerInvitations').insertOne(
              state,
              opts,
            );
          await this.collection('tenantExplorerAudit').insertOne(
            {
              id: randomUUID(),
              environment: s.environment,
              tenantId: s.tenantId,
              action: 'tenant.mongodb.configured',
              actor: actor.subject,
              resource: 'runtime-mongodb',
              revision: tenant.definition.configRevision,
              at: new Date().toISOString(),
            },
            opts,
          );
          live();
          return {
            configured: true,
            editable: true,
            available: true,
            revision: this.revision(sealed),
            source: existing ? 'runtime' : 'pending',
            requiresReload: true,
            onboardingRevision: state.revision,
          } as MongoConfigurationStatus;
        },
        {
          readPreference: 'primary',
          readConcern: { level: 'snapshot' },
          writeConcern: { w: 'majority', wtimeoutMS: 5000 },
          maxCommitTimeMS: 3000,
        },
      );
    } finally {
      await session.endSession();
    }
  }
}
