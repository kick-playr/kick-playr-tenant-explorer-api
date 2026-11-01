import {
  databaseTargetId,
  deletionTargetCollection,
} from '../database-target.js';
import { ConflictException, NotFoundException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { MongoClient, type ClientSession, type Document } from 'mongodb';
import { emptyMetadata, type Aggregate } from '../contracts.js';
import {
  decodeRuntimeEnvelope,
  encodeRuntimeEnvelope,
  type RuntimeEnvelope,
} from '../runtime-configuration.js';
import {
  location,
  parseManifests,
  scopeKey,
  type DeletionStore,
  type DeletionTransaction,
  type DeletionState,
  type Operation,
  type PurgePort,
  type ResolvedManifest,
  type Scope,
} from './contracts.js';
import type { InvitationState } from '../invitations/types.js';

export function pruneRuntime(payload: Record<string, any>, s: Scope) {
  const copy = structuredClone(payload);
  // The current encrypted runtime envelope is development-only. No cross-environment IDs.
  if (s.environment === 'development') {
    for (const field of ['tenants', 'pendingMongoBindings'])
      if (Array.isArray(copy[field]))
        copy[field] = copy[field].filter(
          (t: any) => (t.id ?? t.tenantId) !== s.tenantId,
        );
  }
  const explorer = copy.explorer;
  if (explorer) {
    for (const field of ['clubRuntimes', 'setupRuntimes'])
      if (Array.isArray(explorer[field]))
        explorer[field] = explorer[field].filter(
          (t: any) =>
            !(t.environment === s.environment && t.tenantId === s.tenantId),
        );
    if (Array.isArray(explorer.keyBindings?.bindings))
      explorer.keyBindings.bindings = explorer.keyBindings.bindings.filter(
        (t: any) =>
          !(t.environment === s.environment && t.tenantId === s.tenantId),
      );
  }
  return copy;
}
export async function validateRuntimeTargets(
  payload: Record<string, any>,
  m: ResolvedManifest,
  s: Scope,
) {
  if (
    !Array.isArray(payload.tenants) ||
    !Array.isArray(payload.pendingMongoBindings ?? [])
  )
    throw new ConflictException('Runtime database inventory unavailable');
  const bindings = [
    ...payload.tenants,
    ...((payload.pendingMongoBindings as any[]) ?? []),
  ];
  const mine =
    s.environment === 'development'
      ? bindings.filter((t) => (t.id ?? t.tenantId) === s.tenantId)
      : [];
  for (const t of bindings) {
    if (!t || typeof t.mongoUri !== 'string')
      throw new ConflictException(
        'Runtime database ownership inventory incomplete',
      );
    const parsed = new (
      await import('mongodb-connection-string-url')
    ).ConnectionString(t.mongoUri);
    const db = decodeURIComponent(parsed.pathname.slice(1));
    const loc = location(t.mongoUri, db);
    if (
      (s.environment !== 'development' ||
        (t.id ?? t.tenantId) !== s.tenantId) &&
      m.targets.some((x) => x.location === loc)
    )
      throw new ConflictException('Database is referenced by another tenant');
  }
  for (const t of mine) {
    const parsed = new (
      await import('mongodb-connection-string-url')
    ).ConnectionString(t.mongoUri);
    const loc = location(
      t.mongoUri,
      decodeURIComponent(parsed.pathname.slice(1)),
    );
    if (!m.targets.some((x) => x.location === loc))
      throw new ConflictException(
        'Runtime database missing from deletion inventory',
      );
  }
}
/** Owns the same control database session as tenant lifecycle and invitation fences. */
export class MongoDeletionStore implements DeletionStore {
  constructor(
    private readonly client: MongoClient,
    private readonly database: string,
    private readonly key: Buffer,
    private readonly manifests: readonly ResolvedManifest[],
  ) {}
  private collection(name: string) {
    return this.client.db(this.database).collection<Document>(name);
  }
  private async load(s: Scope, session: ClientSession): Promise<DeletionState> {
    const opts = { session, maxTimeMS: 5000, projection: { _id: 0 } },
      filter = { environment: s.environment, tenantId: s.tenantId };
    const definition = await this.collection('tenantDefinitions').findOne(
      { environment: s.environment, id: s.tenantId },
      opts,
    );
    if (!definition) throw new NotFoundException('Tenant not found');
    const authority = await this.collection('tenantRuntimeAuthorities').findOne(
        filter,
        opts,
      ),
      metadata = await this.collection('tenantExplorerConfiguration').findOne(
        filter,
        opts,
      ),
      operation = await this.collection('tenantDeletionOperations').findOne(
        { _id: scopeKey(s) as never },
        opts,
      ),
      invitations = await this.collection('tenantManagerInvitations').findOne(
        { _id: scopeKey(s) as never },
        opts,
      );
    return {
      tenant: {
        definition,
        authority,
        metadata: { ...emptyMetadata(), ...metadata },
      } as unknown as Aggregate,
      ...(operation ? { operation: operation as unknown as Operation } : {}),
      ...(invitations
        ? { invitations: invitations as unknown as InvitationState }
        : {}),
    };
  }
  private async reserveTargets(
    s: Scope,
    operationId: string,
    revision: string,
    session: ClientSession,
  ) {
    const manifest = this.manifests.find(
      (m) => m.environment === s.environment && m.tenantId === s.tenantId,
    );
    if (!manifest || manifest.digest !== revision)
      throw new ConflictException(
        'Verified database reservation inventory unavailable',
      );
    const opts = { session, maxTimeMS: 5000 };
    const root = await this.client
      .db(this.database)
      .collection<RuntimeEnvelope>('tenantWorkflowConfiguration')
      .findOne({ _id: 'runtime:development' }, opts);
    await validateRuntimeTargets(
      decodeRuntimeEnvelope(root, this.key, this.database),
      manifest,
      s,
    );
    for (const target of [...manifest.targets].sort((a, b) =>
      a.location.localeCompare(b.location),
    )) {
      const collection = this.collection(deletionTargetCollection),
        _id = databaseTargetId(target.uri, target.database) as never;
      const current = await collection.findOne({ _id }, opts);
      if (
        current?.operationId &&
        (current.operationId !== operationId ||
          current.environment !== s.environment ||
          current.tenantId !== s.tenantId ||
          current.manifestRevision !== revision)
      )
        throw new ConflictException(
          'Database is reserved by another deletion operation',
        );
      // This write conflicts with RuntimeMongoService.save in the SAME target document.
      await collection.updateOne(
        { _id },
        {
          $set: {
            operationId,
            environment: s.environment,
            tenantId: s.tenantId,
            manifestRevision: revision,
          },
          $inc: { writeFence: 1 },
        },
        { ...opts, upsert: true },
      );
    }
  }
  async transact<T>(
    s: Scope,
    work: (
      state: DeletionState,
      transaction: DeletionTransaction,
    ) => Promise<T>,
  ): Promise<T> {
    scopeKey(s);
    const session = this.client.startSession();
    try {
      return await session.withTransaction(
        async () => {
          const state = await this.load(s, session),
            before = structuredClone(state),
            value = await work(state, {
              reserveTargets: (operationId, revision) =>
                this.reserveTargets(s, operationId, revision, session),
            });
          if (JSON.stringify(before) === JSON.stringify(state)) return value;
          const opts = { session, maxTimeMS: 5000 },
            d = state.tenant.definition,
            filter = { environment: s.environment, tenantId: s.tenantId };
          const {
            invitationFence: _invitationFence,
            writeFence: _writeFence,
            ...definitionFields
          } = d as typeof d & { invitationFence?: number; writeFence?: number };
          void _invitationFence;
          void _writeFence;
          const fenced = await this.collection('tenantDefinitions').updateOne(
            {
              environment: s.environment,
              id: s.tenantId,
              configRevision: before.tenant.definition.configRevision,
            },
            {
              $set: definitionFields,
              $inc: { invitationFence: 1 },
              ...(!d.deletionId ? { $unset: { deletionId: '' } } : {}),
            },
            opts,
          );
          if (fenced.matchedCount !== 1)
            throw new ConflictException('Tenant changed');
          if (state.tenant.authority) {
            const saved = await this.collection(
              'tenantRuntimeAuthorities',
            ).updateOne(
              {
                ...filter,
                authorityRevision: before.tenant.authority?.authorityRevision,
              },
              { $set: state.tenant.authority },
              opts,
            );
            if (saved.matchedCount !== 1)
              throw new ConflictException('Tenant authority changed');
          }
          if (d.configRevision !== before.tenant.definition.configRevision)
            await this.collection('tenantHostBindings').updateMany(
              filter,
              { $set: { configRevision: d.configRevision } },
              opts,
            );
          if (state.operation)
            await this.collection('tenantDeletionOperations').replaceOne(
              { _id: scopeKey(s) as never },
              { ...state.operation, _id: scopeKey(s) as never },
              { ...opts, upsert: true },
            );
          if (state.invitations)
            await this.collection('tenantManagerInvitations').replaceOne(
              { _id: scopeKey(s) as never },
              { ...state.invitations, _id: scopeKey(s) as never },
              opts,
            );
          if (state.event)
            await this.collection('tenantExplorerAudit').insertOne(
              {
                id: randomUUID(),
                ...filter,
                ...state.event,
                revision: d.configRevision,
                at: new Date().toISOString(),
              },
              opts,
            );
          return value;
        },
        {
          readConcern: { level: 'snapshot' },
          writeConcern: { w: 'majority', wtimeoutMS: 5000 },
          readPreference: 'primary',
          maxCommitTimeMS: 5000,
        },
      );
    } finally {
      await session.endSession();
    }
  }
  async finish(s: Scope, id: string, lease: string) {
    const session = this.client.startSession();
    try {
      await session.withTransaction(
        async () => {
          const opts = { session, maxTimeMS: 5000 },
            x = await this.load(s, session),
            op = x.operation;
          if (
            !op ||
            op.id !== id ||
            op.phase !== 'purging' ||
            op.leaseId !== lease ||
            Number(op.leaseUntil) <= Date.now() ||
            op.targets.some((t) => !t.done)
          )
            throw new ConflictException(
              'Deletion lease or database verification changed',
            );
          const manifest = this.manifests.find(
            (m) => m.environment === s.environment && m.tenantId === s.tenantId,
          );
          if (!manifest || manifest.digest !== op.manifestRevision)
            throw new ConflictException('Deletion inventory changed');
          for (const target of manifest.targets) {
            const reservation = await this.collection(
              deletionTargetCollection,
            ).findOne(
              { _id: databaseTargetId(target.uri, target.database) as never },
              opts,
            );
            if (
              reservation?.operationId !== id ||
              reservation.environment !== s.environment ||
              reservation.tenantId !== s.tenantId ||
              reservation.manifestRevision !== manifest.digest
            )
              throw new ConflictException('Database reservation changed');
          }

          const root = await this.client
            .db(this.database)
            .collection<RuntimeEnvelope>('tenantWorkflowConfiguration')
            .findOne({ _id: 'runtime:development' }, opts);
          const payload = decodeRuntimeEnvelope(root, this.key, this.database);
          const sealed = encodeRuntimeEnvelope(
            pruneRuntime(payload, s),
            this.key,
            this.database,
          );
          const updated = await this.client
            .db(this.database)
            .collection<RuntimeEnvelope>('tenantWorkflowConfiguration')
            .replaceOne(root!, sealed, opts);
          if (updated.matchedCount !== 1)
            throw new ConflictException('Runtime configuration changed');
          const filter = { environment: s.environment, tenantId: s.tenantId };
          for (const name of [
            'tenantExplorerConfiguration',
            'tenantRuntimeAuthorities',
            'tenantHostBindings',
            'tenantExplorerAudit',
            'tenantManagerSetupProofs',
            'tenantApiKeys',
            'tenantApiKeyManagers',
            ...manifest.scopedCollections,
          ]) {
            await this.collection(name).deleteMany(filter, opts);
            if (await this.collection(name).countDocuments(filter, opts))
              throw new ConflictException('Scoped cleanup verification failed');
          }
          await this.collection('tenantManagerInvitations').deleteOne(
            { _id: scopeKey(s) as never },
            opts,
          );
          const d = x.tenant.definition;
          const result = await this.collection('tenantDefinitions').replaceOne(
            {
              environment: s.environment,
              id: s.tenantId,
              configRevision: d.configRevision,
              deletionId: id,
            },
            {
              id: s.tenantId,
              environment: s.environment,
              status: 'disabled',
              deletionId: id,
              configRevision: d.configRevision,
              hostname: `${s.tenantId}.invalid`,
              aliases: [],
              public: { name: 'Deleted tenant', locale: 'de-CH' },
              secretReferences: { mongoUri: 'deleted', key: 'deleted' },
            },
            opts,
          );
          if (result.matchedCount !== 1)
            throw new ConflictException('Tenant changed');
          await this.collection('tenantExplorerAudit').insertOne(
            {
              id: randomUUID(),
              ...filter,
              action: 'tenant.deletion.purged',
              actor: op.actor ?? 'deletion-operation',
              resource: id,
              revision: d.configRevision,
              at: new Date().toISOString(),
            },
            opts,
          );
        },
        {
          readConcern: { level: 'snapshot' },
          writeConcern: { w: 'majority', wtimeoutMS: 5000 },
          readPreference: 'primary',
          maxCommitTimeMS: 5000,
        },
      );
    } finally {
      await session.endSession();
    }
  }
}
/** Connections and targets are operator-owned. No request input reaches db()/dropDatabase(). */
export class MongoPurgePort implements PurgePort {
  readonly manifests: ResolvedManifest[];
  constructor(
    private readonly control: MongoClient,
    private readonly database: string,
    private readonly key: Buffer,
    input: unknown,
    env: NodeJS.ProcessEnv,
  ) {
    this.manifests = parseManifests(input, env, database);
  }
  private manifest(s: Scope) {
    return this.manifests.find(
      (m) => m.environment === s.environment && m.tenantId === s.tenantId,
    );
  }
  async inventory(s: Scope) {
    const m = this.manifest(s);
    if (!m)
      return {
        revision: 'unconfigured',
        complete: false,
        targets: [],
        reason:
          'An operator must configure a complete verified deletion inventory',
      };
    const row = await this.control
      .db(this.database)
      .collection<RuntimeEnvelope>('tenantWorkflowConfiguration')
      .findOne(
        { _id: 'runtime:development' },
        { readPreference: 'primary', maxTimeMS: 5000 },
      );
    const payload = decodeRuntimeEnvelope(row, this.key, this.database);
    await validateRuntimeTargets(payload, m, s);
    return {
      revision: m.digest,
      complete: true,
      targets: m.targets.map((t) => ({
        id: t.id,
        label: `Database ${t.database}`,
      })),
    };
  }
  private async reservation(
    s: Scope,
    target: ResolvedManifest['targets'][number],
  ) {
    const opts = { readPreference: 'primary' as const, maxTimeMS: 5000 };
    const operation = await this.control
      .db(this.database)
      .collection('tenantDeletionOperations')
      .findOne({ _id: scopeKey(s) as never }, opts);
    const reservation = await this.control
      .db(this.database)
      .collection(deletionTargetCollection)
      .findOne(
        { _id: databaseTargetId(target.uri, target.database) as never },
        opts,
      );
    if (
      !operation ||
      operation.phase !== 'purging' ||
      !operation.leaseId ||
      Number(operation.leaseUntil) <= Date.now() ||
      operation.manifestRevision !== this.manifest(s)?.digest ||
      reservation?.operationId !== operation.id ||
      reservation?.environment !== s.environment ||
      reservation?.tenantId !== s.tenantId ||
      reservation?.manifestRevision !== operation.manifestRevision
    )
      throw new ConflictException(
        'Matching active database deletion reservation required',
      );
  }
  private async target<T>(
    s: Scope,
    id: string,
    work: (client: MongoClient, database: string) => Promise<T>,
  ): Promise<T> {
    await this.inventory(s);
    const t = this.manifest(s)?.targets.find((t) => t.id === id);
    if (!t) throw new ConflictException('Database target unavailable');
    await this.reservation(s, t);
    const client = new MongoClient(t.uri, {
      connectTimeoutMS: 5000,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 10000,
      readPreference: 'primary',
      maxPoolSize: 1,
    });
    try {
      await client.connect();
      await this.reservation(s, t);
      await this.inventory(s);
      return await work(client, t.database);
    } finally {
      await client.close();
    }
  }
  erase(s: Scope, id: string) {
    return this.target(s, id, async (c, d) => {
      await c.db(d).dropDatabase({ maxTimeMS: 10000 });
    });
  }
  absent(s: Scope, id: string) {
    return this.target(s, id, async (c, d) => {
      const result = await c
        .db('admin')
        .admin()
        .listDatabases({
          nameOnly: true,
          filter: { name: { $regex: `^${d}$`, $options: 'i' } },
          maxTimeMS: 5000,
        });
      return result.databases.length === 0;
    });
  }
}
