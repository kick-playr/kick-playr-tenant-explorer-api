import { fenceDatabaseAssignment } from './database-target.js';
import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';
import {
  createHash,
  randomUUID,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';
import {
  KeyFileRegistry,
  runtimeKeyBindings,
  type KeyBinding,
} from './key-files.js';
import { KEY_KINDS, keyBindingProof } from './key-binding-proof.js';
import type { SetupRuntimePort } from './onboarding/runtime.js';
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
    private readonly environment: NodeJS.ProcessEnv = process.env,
    private readonly keyRuntime?: SetupRuntimePort,
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
  private async envelope(opts: Record<string, unknown>) {
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
    if (payload.version !== 2 || !row) throw unavailable();
    return { row, payload };
  }
  private async root(opts: Record<string, unknown>) {
    const { row, payload } = await this.envelope(opts);
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
      editable:
        tenant.editable &&
        tenant.definition.secretReferences?.mongoUri ===
          `workflow-local:${s.tenantId}:mongo`,
      available: true,
      revision: this.revision(root.row),
      source,
      requiresReload: source !== null,
      onboardingRevision: tenant.invitations?.revision ?? 0,
    };
  }
  private async persist(
    s: Scope,
    root: Awaited<ReturnType<RuntimeMongoService['root']>>,
    tenant: Awaited<ReturnType<RuntimeMongoService['tenant']>>,
    opts: Record<string, unknown>,
    actor: { subject: string | undefined },
    action: string,
    resource: string,
  ) {
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
    const sealed = encodeRuntimeEnvelope(root.payload, this.key, this.database);
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
      await this.collection('tenantManagerInvitations').insertOne(state, opts);
    await this.collection('tenantExplorerAudit').insertOne(
      {
        id: randomUUID(),
        environment: s.environment,
        tenantId: s.tenantId,
        action,
        actor: actor.subject,
        resource,
        revision: tenant.definition.configRevision,
        at: new Date().toISOString(),
      },
      opts,
    );
    return {
      revision: this.revision(sealed),
      onboardingRevision: state.revision as number,
    };
  }

  async loadKeyBindings(): Promise<KeyBinding[]> {
    this.active();
    const root = await this.envelope({ maxTimeMS: 3000 });
    return this.bindings(root);
  }
  private bindings(root: { payload: Record<string, unknown> }) {
    const explorer = root.payload.explorer as any;
    if (
      !explorer ||
      explorer.keyBindings?.version !== 1 ||
      !Array.isArray(explorer.keyBindings.bindings)
    )
      throw unavailable();
    const bindings = runtimeKeyBindings(
      root.payload,
      this.database,
      explorer.keyBindings.bindings,
    );
    new KeyFileRegistry(bindings, this.database, this.environment);
    return bindings;
  }
  private candidate(
    s: Scope,
    root: Awaited<ReturnType<RuntimeMongoService['root']>>,
    tenant: Awaited<ReturnType<RuntimeMongoService['tenant']>>,
  ): KeyBinding {
    const reference = tenant.definition.secretReferences?.key;
    if (
      s.environment !== 'development' ||
      reference !== `workflow-local:${s.tenantId}:key`
    )
      throw new BadRequestException('Tenant key adapter unavailable');
    const prefix = `WORKFLOW_REAL_${s.tenantId.replace(/-/g, '_').toUpperCase()}`;
    const binding = this.bindings(root).find(
      (b) =>
        b.environment === s.environment &&
        b.tenantId === s.tenantId &&
        b.controlDatabase === this.database &&
        b.keyReference === reference,
    ) ?? {
      ...s,
      environment: 'development' as const,
      controlDatabase: this.database,
      keyReference: reference,
      version: 'v1',
      profile: String(root.payload.profile),
      variables: {
        wrapping: `${prefix}_WRAPPING_KEY_V1`,
        index: `${prefix}_INDEX_KEY`,
        control: `${prefix}_CONTROL_KEY`,
      },
    };
    if (binding.version !== 'v1' || binding.profile !== root.payload.profile)
      throw new BadRequestException('Tenant key adapter unavailable');
    return binding;
  }
  async keyStatus(s: Scope) {
    this.scope(s);
    this.active();
    if (s.environment !== 'development')
      return {
        available: false,
        editable: false,
        registered: false,
        revision: null,
        local: null,
      };
    const root = await this.root({ maxTimeMS: 3000 }),
      tenant = await this.tenant(s, { maxTimeMS: 3000 }),
      binding = this.candidate(s, root, tenant);
    return {
      available: !!this.keyRuntime,
      editable: tenant.editable && !!this.keyRuntime,
      registered: this.bindings(root).some(
        (b) =>
          b.tenantId === s.tenantId &&
          b.environment === s.environment &&
          b.controlDatabase === this.database &&
          b.keyReference === binding.keyReference,
      ),
      revision: this.revision(root.row),
      local: await new KeyFileRegistry(
        [binding],
        this.database,
        this.environment,
      ).describe(tenant.definition as any),
      onboardingRevision: tenant.invitations?.revision ?? 0,
    };
  }
  private localProofs(
    binding: KeyBinding,
    configRevision: number,
    challenge: string,
    expiresAt: number,
    others: KeyBinding[] = [],
  ) {
    const owned: Buffer[] = [],
      transport = Buffer.from(
        this.environment.MANAGER_SETUP_CONTROL_KEY ?? '',
        'base64',
      );
    try {
      for (const kind of KEY_KINDS) {
        const value = this.environment[binding.variables[kind]],
          key = Buffer.from(value ?? '', 'base64');
        owned.push(key);
        const suffix = {
          wrapping: 'WRAPPING_KEY_V1',
          index: 'INDEX_KEY',
          control: 'CONTROL_KEY',
        }[kind];
        if (
          !binding.variables[kind].endsWith(suffix) ||
          key.length !== 32 ||
          key.toString('base64') !== value ||
          key.equals(this.key) ||
          key.equals(transport) ||
          owned.slice(0, -1).some((other) => other.equals(key))
        )
          throw new BadRequestException(
            'Three valid independent tenant keys are required in this API environment',
          );
      }
      for (const other of others.filter(
        (other) =>
          other.environment === binding.environment &&
          other.controlDatabase === binding.controlDatabase &&
          other.tenantId !== binding.tenantId,
      )) {
        for (const name of Object.values(other.variables)) {
          const bytes = Buffer.from(this.environment[name] ?? '', 'base64');
          try {
            if (owned.some((key) => key.equals(bytes)))
              throw new BadRequestException(
                'Tenant keys must not be shared between tenants',
              );
          } finally {
            bytes.fill(0);
          }
        }
      }
      const proofBinding = { ...binding, configRevision, expiresAt };
      return Object.fromEntries(
        KEY_KINDS.map((kind, index) => [
          kind,
          keyBindingProof(
            owned[index]!,
            proofBinding,
            challenge,
            kind,
            binding.variables[kind],
          ),
        ]),
      );
    } finally {
      owned.forEach((key) => key.fill(0));
      transport.fill(0);
    }
  }
  async configureKeys(
    s: Scope,
    body: unknown,
    actor: {
      issuer: string | undefined;
      subject: string | undefined;
      expiresAt: number | undefined;
    },
  ) {
    this.scope(s);
    this.active();
    const input = parse(inputSchema.omit({ uri: true }), body);
    const live = () => {
      this.active();
      if (
        !actor.issuer ||
        !actor.subject ||
        !Number.isSafeInteger(actor.expiresAt) ||
        actor.expiresAt! <= Date.now()
      )
        throw new ForbiddenException('Platform authorization expired');
    };
    live();
    if (!this.keyRuntime) throw unavailable();
    const initial = await this.root({ maxTimeMS: 3000 }),
      tenant = await this.tenant(s, { maxTimeMS: 3000 }),
      candidate = this.candidate(s, initial, tenant);
    if (!tenant.editable)
      throw new ConflictException(
        'Configure keys before the first manager invitation',
      );
    if (this.revision(initial.row) !== input.expectedRevision) throw conflict();
    const challenge = randomBytes(32).toString('base64url');
    this.localProofs(
      candidate,
      tenant.definition.configRevision,
      challenge,
      Date.now() + 30000,
      this.bindings(initial),
    );
    // Network checks never run inside the retried Mongo transaction.
    const proof = parse(
      z.strictObject({
        environment: z.literal(s.environment),
        tenantId: z.literal(s.tenantId),
        configRevision: z.literal(tenant.definition.configRevision),
        keyReference: z.literal(candidate.keyReference),
        expiresAt: z.number().int().positive(),
        variables: z.strictObject({
          wrapping: z.literal(candidate.variables.wrapping),
          index: z.literal(candidate.variables.index),
          control: z.literal(candidate.variables.control),
        }),
        proofs: z.strictObject({
          wrapping: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
          index: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
          control: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
        }),
      }),
      await this.keyRuntime.request(
        s,
        {
          issuer: actor.issuer!,
          subject: actor.subject!,
          membershipId: 'platform',
          expiresAt: actor.expiresAt,
        },
        'key-check',
        { challenge },
      ),
    );
    if (
      proof.expiresAt > actor.expiresAt! ||
      proof.expiresAt > Date.now() + 30000
    )
      throw new BadRequestException('Invalid runtime key proof');
    const validate = (binding: KeyBinding, revision: number) => {
      live();
      if (proof.expiresAt <= Date.now())
        throw new ForbiddenException('Runtime key check expired; try again');
      if (
        revision !== proof.configRevision ||
        binding.keyReference !== proof.keyReference ||
        KEY_KINDS.some(
          (kind) => binding.variables[kind] !== proof.variables[kind],
        )
      )
        throw conflict();
      const expected = this.localProofs(
        binding,
        revision,
        challenge,
        proof.expiresAt,
        this.bindings(initial),
      );
      if (
        KEY_KINDS.some(
          (kind) =>
            !timingSafeEqual(
              Buffer.from(expected[kind]!, 'base64url'),
              Buffer.from(proof.proofs[kind], 'base64url'),
            ),
        )
      )
        throw new BadRequestException(
          'Tenant API and runtime API keys do not match',
        );
    };
    validate(candidate, tenant.definition.configRevision);
    const session = this.client.startSession();
    try {
      return await session.withTransaction(
        async () => {
          live();
          const opts = { session, maxTimeMS: 3000 },
            root = await this.root(opts),
            current = await this.tenant(s, opts);
          if (
            !current.editable ||
            this.revision(root.row) !== input.expectedRevision
          )
            throw conflict();
          const binding = this.candidate(s, root, current);
          validate(binding, current.definition.configRevision);
          const explorer = root.payload.explorer as any;
          const previous = explorer.keyBindings.bindings.find(
            (b: any) =>
              b.tenantId === s.tenantId &&
              b.environment === s.environment &&
              b.controlDatabase === this.database &&
              b.keyReference === binding.keyReference,
          );
          // Binding an existing key is not a rotation: an existing mapping must remain identical.
          if (
            previous &&
            ([
              'tenantId',
              'environment',
              'controlDatabase',
              'keyReference',
              'version',
              'profile',
            ].some(
              (field) => previous[field] !== binding[field as keyof KeyBinding],
            ) ||
              KEY_KINDS.some(
                (kind) => previous.variables[kind] !== binding.variables[kind],
              ))
          )
            throw conflict();
          if (!previous) explorer.keyBindings.bindings.push(binding);
          this.bindings(root);
          const result = await this.persist(
            s,
            root,
            current,
            opts,
            actor,
            'tenant.keys.configured',
            'runtime-keys',
          );
          validate(binding, current.definition.configRevision);
          return {
            ...result,
            available: true,
            editable: true,
            registered: true,
            local: await new KeyFileRegistry(
              [binding],
              this.database,
              this.environment,
            ).describe(current.definition as any),
          };
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
          if (
            !tenant.editable ||
            tenant.definition.secretReferences?.mongoUri !==
              `workflow-local:${s.tenantId}:mongo`
          )
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
          await fenceDatabaseAssignment(
            this.client,
            this.database,
            input.uri,
            cluster(input.uri).database,
            session,
          );
          const pending = root.pending.filter((t) => t.tenantId !== s.tenantId);
          if (existing) existing.mongoUri = input.uri;
          else pending.push({ tenantId: s.tenantId, mongoUri: input.uri });
          if (pending.length > 32)
            throw new BadRequestException('Provisioning draft limit reached');
          if (pending.length) root.payload.pendingMongoBindings = pending;
          else delete root.payload.pendingMongoBindings;
          const saved = await this.persist(
            s,
            root,
            tenant,
            opts,
            actor,
            'tenant.mongodb.configured',
            'runtime-mongodb',
          );
          live();
          return {
            configured: true,
            editable: true,
            available: true,
            revision: saved.revision,
            source: existing ? 'runtime' : 'pending',
            requiresReload: true,
            onboardingRevision: saved.onboardingRevision,
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
