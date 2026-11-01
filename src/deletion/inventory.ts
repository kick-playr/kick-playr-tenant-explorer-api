import { ConflictException } from '@nestjs/common';
import { createHash } from 'node:crypto';
import { ConnectionString } from 'mongodb-connection-string-url';
import type { ClientSession, Document, MongoClient } from 'mongodb';
import { z } from 'zod';
import { identifier } from '../contracts.js';
import { databaseLocation, databaseTargetId } from '../database-target.js';
import {
  decodeRuntimeEnvelope,
  type RuntimeEnvelope,
} from '../runtime-configuration.js';
import { CredentialVault } from '../vault.js';
import { scopeKey, type Scope } from './contracts.js';
export const snapshotCollection = 'tenantDeletionSnapshots';
export interface RegisteredTarget {
  id: string;
  uri: string;
  database: string;
  location: string;
}
export interface RegisteredInventory {
  digest: string;
  controlOnly: boolean;
  targets: RegisteredTarget[];
  scopedCollections: readonly string[];
}
const invalid = () =>
  new ConflictException(
    'Registered database inventory is invalid or ambiguous; review runtime configuration',
  );
function records(payload: Record<string, any>, control: string) {
  if (
    payload.version !== 2 ||
    !['workflow-real', 'workflow-local'].includes(payload.profile) ||
    !Array.isArray(payload.tenants) ||
    payload.tenants.length > 32 ||
    !Array.isArray(payload.pendingMongoBindings ?? []) ||
    (payload.pendingMongoBindings ?? []).length > 32
  )
    throw invalid();
  const all: { tenantId: string; source: string; target: RegisteredTarget }[] =
    [];
  for (const [source, rows] of [
    ['tenants', payload.tenants],
    ['pendingMongoBindings', payload.pendingMongoBindings ?? []],
  ] as const) {
    const seen = new Set<string>();
    for (const row of rows) {
      if (
        !row ||
        typeof row !== 'object' ||
        Array.isArray(row) ||
        (row.environment !== undefined && row.environment !== 'development')
      )
        throw invalid();
      const id = source === 'tenants' ? row.id : row.tenantId;
      if (
        (source === 'tenants' &&
          row.tenantId !== undefined &&
          row.tenantId !== id) ||
        (source === 'pendingMongoBindings' &&
          row.id !== undefined &&
          row.id !== id) ||
        !identifier.safeParse(id).success ||
        seen.has(id) ||
        typeof row.mongoUri !== 'string' ||
        !row.mongoUri ||
        row.mongoUri.length > 8192 ||
        /[\x00-\x20\x7f]/.test(row.mongoUri)
      )
        throw invalid();
      seen.add(id);
      let parsed: ConnectionString;
      try {
        parsed = new ConnectionString(row.mongoUri);
      } catch {
        throw invalid();
      }
      const database = decodeURIComponent(parsed.pathname.slice(1));
      if (
        parsed.hash ||
        !/^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$/.test(database) ||
        ['admin', 'local', 'config', control.toLowerCase()].includes(
          database.toLowerCase(),
        )
      )
        throw invalid();
      const location = databaseLocation(row.mongoUri, database);
      all.push({
        tenantId: id,
        source,
        target: {
          id: databaseTargetId(row.mongoUri, database),
          database,
          uri: row.mongoUri,
          location,
        },
      });
    }
  }
  const locations = new Map<string, (typeof all)[number]>();
  for (const row of all) {
    const previous = locations.get(row.target.location);
    if (
      previous &&
      (previous.tenantId !== row.tenantId ||
        previous.target.uri !== row.target.uri ||
        previous.target.database !== row.target.database)
    )
      throw new ConflictException(
        'Registered database is shared or ambiguous between tenant bindings',
      );
    locations.set(row.target.location, row);
  }
  return all;
}
export function deriveInventory(
  payload: Record<string, any>,
  scope: Scope,
  control: string,
): RegisteredInventory {
  scopeKey(scope);
  if (scope.environment !== 'development')
    throw new ConflictException(
      'Registered database cleanup is unsupported for this environment',
    );
  const all = records(payload, control),
    selected = all.filter((r) => r.tenantId === scope.tenantId),
    targets = [
      ...new Map(selected.map((r) => [r.target.location, r.target])).values(),
    ].sort((a, b) => a.location.localeCompare(b.location));
  const normalized = all
    .map((r) => ({ tenantId: r.tenantId, source: r.source, ...r.target }))
    .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
  return {
    digest: createHash('sha256')
      .update(
        JSON.stringify({
          version: 'registered-v1',
          scope: scopeKey(scope),
          bindings: normalized,
        }),
      )
      .digest('hex'),
    controlOnly: targets.length === 0,
    targets,
    scopedCollections: [],
  };
}
function binding(s: Scope, id: string, revision: string) {
  return JSON.stringify([
    'tenant-deletion-snapshot-v1',
    s.environment,
    s.tenantId,
    id,
    revision,
  ]);
}
const frozenSchema = z.strictObject({
  version: z.literal(1),
  environment: z.literal('development'),
  tenantId: identifier,
  operationId: z.string().min(1),
  revision: z.string().regex(/^[a-f0-9]{64}$/),
  targets: z
    .array(
      z.strictObject({
        id: z.string().regex(/^[a-f0-9]{64}$/),
        uri: z.string().min(1).max(8192),
        database: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$/),
        location: z.string().min(1),
      }),
    )
    .max(64),
});
/** One resolver shared by store and purger. No request mutates target configuration. */
export class DeletionInventoryResolver {
  constructor(
    private readonly client: MongoClient,
    private readonly database: string,
    private readonly key: Buffer,
    private readonly vault: CredentialVault,
  ) {}
  private collection(name: string) {
    return this.client.db(this.database).collection<Document>(name);
  }
  private opts(session?: ClientSession) {
    return {
      ...(session ? { session } : {}),
      readPreference: 'primary' as const,
      maxTimeMS: 5000,
    };
  }
  private async current(s: Scope, session?: ClientSession) {
    if (s.environment !== 'development')
      throw new ConflictException(
        'Registered database cleanup is unsupported for this environment',
      );
    const root = await this.client
      .db(this.database)
      .collection<RuntimeEnvelope>('tenantWorkflowConfiguration')
      .findOne({ _id: 'runtime:development' }, this.opts(session));
    let payload;
    try {
      payload = decodeRuntimeEnvelope(root, this.key, this.database);
    } catch {
      throw invalid();
    }
    return deriveInventory(payload, s, this.database);
  }
  private async frozen(
    s: Scope,
    op: { id: string; manifestRevision?: string },
    session?: ClientSession,
  ) {
    const row = await this.collection(snapshotCollection).findOne(
      { _id: `${scopeKey(s)}/${op.id}` as never },
      this.opts(session),
    );
    try {
      if (
        !row ||
        row.environment !== s.environment ||
        row.tenantId !== s.tenantId ||
        row.operationId !== op.id ||
        row.inventoryRevision !== op.manifestRevision
      )
        throw Error();
      const parsed = frozenSchema.parse(
        JSON.parse(
          this.vault.open(
            binding(s, op.id, op.manifestRevision!),
            row.envelope,
          ),
        ),
      );
      if (
        parsed.environment !== s.environment ||
        parsed.tenantId !== s.tenantId ||
        parsed.operationId !== op.id ||
        parsed.revision !== op.manifestRevision
      )
        throw Error();
      const checked = deriveInventory(
        {
          version: 2,
          profile: 'workflow-real',
          tenants: parsed.targets.map((t, i) => ({
            id: `snapshot-${i}`,
            mongoUri: t.uri,
          })),
          pendingMongoBindings: [],
        },
        s,
        this.database,
      );
      void checked;
      const seen = new Set<string>();
      for (const t of parsed.targets) {
        if (
          t.id !== databaseTargetId(t.uri, t.database) ||
          t.location !== databaseLocation(t.uri, t.database) ||
          decodeURIComponent(new ConnectionString(t.uri).pathname.slice(1)) !==
            t.database ||
          seen.has(t.location)
        )
          throw Error();
        seen.add(t.location);
      }
      return {
        digest: parsed.revision,
        controlOnly: parsed.targets.length === 0,
        targets: parsed.targets,
        scopedCollections: [],
      } as RegisteredInventory;
    } catch {
      throw new ConflictException(
        'Encrypted deletion snapshot unavailable or scope/revision changed; cannot change frozen targets',
      );
    }
  }
  async resolve(
    s: Scope,
    session?: ClientSession,
    operation?: { id: string; phase: string; manifestRevision?: string },
  ) {
    const current = await this.current(s, session);
    const op =
      operation ??
      (await this.collection('tenantDeletionOperations').findOne(
        { _id: scopeKey(s) as never },
        this.opts(session),
      ));
    if (op && ['purging', 'failed'].includes(op.phase) && op.manifestRevision) {
      const frozen = await this.frozen(
        s,
        op as { id: string; manifestRevision: string },
        session,
      );
      for (const t of current.targets)
        if (!frozen.targets.some((f) => f.location === t.location))
          throw new ConflictException(
            'Registered target changed after purge claim',
          );
      const root = await this.client
        .db(this.database)
        .collection<RuntimeEnvelope>('tenantWorkflowConfiguration')
        .findOne({ _id: 'runtime:development' }, this.opts(session));
      const all = records(
        decodeRuntimeEnvelope(root, this.key, this.database),
        this.database,
      );
      for (const r of all)
        if (
          r.tenantId !== s.tenantId &&
          frozen.targets.some((t) => t.location === r.target.location)
        )
          throw new ConflictException(
            'Frozen database is now referenced by another tenant',
          );
      return frozen;
    }
    return current;
  }
  async freeze(
    s: Scope,
    operationId: string,
    revision: string,
    session: ClientSession,
  ) {
    const op = await this.collection('tenantDeletionOperations').findOne(
      { _id: scopeKey(s) as never },
      this.opts(session),
    );
    if (op && ['purging', 'failed'].includes(op.phase) && op.manifestRevision) {
      const frozen = await this.resolve(
        s,
        session,
        op as unknown as {
          id: string;
          phase: string;
          manifestRevision: string;
        },
      );
      if (op.id !== operationId || frozen.digest !== revision)
        throw new ConflictException('Frozen deletion inventory changed');
      return frozen;
    }
    const inventory = await this.current(s, session);
    if (inventory.digest !== revision)
      throw new ConflictException(
        'Registered database inventory changed; review updated preview',
      );
    const id = `${scopeKey(s)}/${operationId}`;
    if (
      await this.collection(snapshotCollection).findOne(
        { _id: id as never },
        this.opts(session),
      )
    )
      throw new ConflictException(
        'Unexpected deletion snapshot; review operation',
      );
    const envelope = this.vault.seal(
      binding(s, operationId, revision),
      JSON.stringify({
        version: 1,
        ...s,
        operationId,
        revision,
        targets: inventory.targets,
      }),
    );
    await this.collection(snapshotCollection).insertOne(
      {
        _id: id as never,
        ...s,
        operationId,
        inventoryRevision: revision,
        envelope,
      },
      this.opts(session),
    );
    return inventory;
  }
  async discard(s: Scope, id: string, session: ClientSession) {
    await this.collection(snapshotCollection).deleteOne(
      { _id: `${scopeKey(s)}/${id}` as never },
      this.opts(session),
    );
  }
}
