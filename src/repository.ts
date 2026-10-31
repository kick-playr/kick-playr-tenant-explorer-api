import { ConflictException, ServiceUnavailableException } from '@nestjs/common';
import { MongoClient, type ClientSession, type Document } from 'mongodb';
import {
  emptyMetadata,
  type Aggregate,
  type AuditEvent,
  type Definition,
  type ListQuery,
  type Authority,
} from './contracts.js';

export interface Transaction {
  read(environment: string, id: string): Promise<Aggregate | null>;
  save(aggregate: Aggregate, expectedRevision: number | null): Promise<void>;
  appendAudit(event: AuditEvent): Promise<void>;
}
export interface Repository {
  clubDefinitions?(issuer: string, subject: string): Promise<Definition[]>;
  read(environment: string, id: string): Promise<Aggregate | null>;
  list(query: ListQuery): Promise<{
    items: Definition[];
    total: number;
    page: number;
    pageSize: number;
  }>;
  audit(environment: string, tenantId: string): Promise<AuditEvent[]>;
  transaction<T>(work: (tx: Transaction) => Promise<T>): Promise<T>;
}
const names = {
  definitions: 'tenantDefinitions',
  hosts: 'tenantHostBindings',
  authorities: 'tenantRuntimeAuthorities',
  configuration: 'tenantExplorerConfiguration',
  audit: 'tenantExplorerAudit',
};
const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
export class MongoRepository implements Repository {
  readonly client: MongoClient;
  private readonly databaseName: string;
  constructor(client: MongoClient, databaseName: string) {
    if (!/^[A-Za-z0-9_-]{1,63}$/.test(databaseName))
      throw new Error('Invalid explorer MongoDB configuration');
    this.databaseName = databaseName;
    this.client = client;
  }
  private collection(name: keyof typeof names) {
    return this.client.db(this.databaseName).collection(names[name]);
  }
  async clubDefinitions(
    issuer: string,
    subject: string,
  ): Promise<Definition[]> {
    const rows = await this.collection('authorities')
      .find(
        {
          schema: 1,
          status: 'active',
          identityRealm: issuer,
          users: {
            $elemMatch: {
              issuer,
              subject,
              status: 'active',
              permissions: {
                $all: ['club:settings:read', 'club:settings:write'],
              },
            },
          },
        },
        { projection: { tenantId: 1, environment: 1 }, maxTimeMS: 3000 },
      )
      .limit(101)
      .toArray();
    if (rows.length > 100)
      throw new ServiceUnavailableException('Club directory limit exceeded');
    const result: Definition[] = [];
    for (const row of rows) {
      const a = await this.read(row.environment, row.tenantId);
      if (a) result.push(a.definition);
    }
    return result;
  }
  async onModuleInit() {
    await this.client.connect();
    await this.collection('definitions').createIndex(
      { environment: 1, id: 1 },
      { unique: true, name: 'control_tenant_environment_id_unique' },
    );
    await this.collection('hosts').createIndex(
      { environment: 1, hostname: 1 },
      { unique: true, name: 'control_tenant_environment_hostname_unique' },
    );
    await this.collection('authorities').createIndex(
      { environment: 1, tenantId: 1 },
      {
        unique: true,
        name: 'control_runtime_authority_environment_tenant_unique',
      },
    );
    await this.collection('configuration').createIndex(
      { environment: 1, tenantId: 1 },
      { unique: true },
    );
    await this.collection('audit').createIndex({
      environment: 1,
      tenantId: 1,
      at: -1,
    });
  }
  async onModuleDestroy() {
    await this.client.close();
  }
  async read(
    environment: string,
    id: string,
    session?: ClientSession,
  ): Promise<Aggregate | null> {
    const options = { session, maxTimeMS: 3000, projection: { _id: 0 } };
    const definition = await this.collection('definitions').findOne(
      { environment, id },
      options,
    );
    if (!definition) return null;
    const authority = await this.collection('authorities').findOne(
      { environment, tenantId: id },
      options,
    );
    const metadata = await this.collection('configuration').findOne(
      { environment, tenantId: id },
      options,
    );
    return {
      definition: definition as unknown as Definition,
      authority: authority as unknown as Authority | null,
      metadata: {
        ...emptyMetadata(),
        ...(metadata && {
          configuration: metadata.configuration ?? {},
          integrations: metadata.integrations ?? [],
          credentials: metadata.credentials ?? [],
        }),
      },
    };
  }
  async list(query: ListQuery) {
    const filter: Document = {};
    if (query.environment) filter.environment = query.environment;
    if (query.status) filter.status = query.status;
    if (query.search)
      filter.$or = ['id', 'public.name', 'hostname', 'aliases'].map((key) => ({
        [key]: { $regex: escape(query.search!), $options: 'i' },
      }));
    const collection = this.collection('definitions');
    const items = await collection
      .find(filter, { projection: { _id: 0 }, maxTimeMS: 3000 })
      .sort({ 'public.name': 1, id: 1, environment: 1 })
      .skip((query.page - 1) * query.pageSize)
      .limit(query.pageSize)
      .toArray();
    const total = await collection.countDocuments(filter, { maxTimeMS: 3000 });
    return {
      items: items as unknown as Definition[],
      total,
      page: query.page,
      pageSize: query.pageSize,
    };
  }
  async audit(environment: string, tenantId: string): Promise<AuditEvent[]> {
    return (await this.collection('audit')
      .find(
        { environment, tenantId },
        { projection: { _id: 0 }, maxTimeMS: 3000 },
      )
      .sort({ at: -1, _id: -1 })
      .limit(100)
      .toArray()) as unknown as AuditEvent[];
  }
  async transaction<T>(work: (tx: Transaction) => Promise<T>): Promise<T> {
    const session = this.client.startSession();
    try {
      return await session.withTransaction(
        async () =>
          work({
            read: (env, id) => this.read(env, id, session),
            save: async (aggregate, expectedRevision) => {
              const { definition, authority, metadata } = aggregate;
              const { environment, id } = definition;
              const options = { session, maxTimeMS: 3000 };
              if (expectedRevision === null)
                await this.collection('definitions').insertOne(
                  definition,
                  options,
                );
              else {
                // Preserve internal writeFence and other runtime-owned fields.
                const { _id, ...fields } = definition as Definition & {
                  _id?: unknown;
                };
                void _id;
                const result = await this.collection('definitions').updateOne(
                  { environment, id, configRevision: expectedRevision },
                  { $set: fields },
                  options,
                );
                if (result.matchedCount !== 1)
                  throw new ConflictException(
                    'Tenant revision changed; reload before saving',
                  );
              }
              await this.collection('hosts').deleteMany(
                { environment, tenantId: id },
                options,
              );
              await this.collection('hosts').insertMany(
                [definition.hostname, ...definition.aliases].map(
                  (hostname) => ({
                    environment,
                    tenantId: id,
                    hostname,
                    configRevision: definition.configRevision,
                  }),
                ),
                options,
              );
              if (authority) {
                const previousAuthorityRevision =
                  authority.authorityRevision - 1;
                if (
                  expectedRevision === null ||
                  previousAuthorityRevision === 0
                ) {
                  await this.collection('authorities').insertOne(
                    authority,
                    options,
                  );
                } else {
                  const result = await this.collection('authorities').updateOne(
                    {
                      environment,
                      tenantId: id,
                      authorityRevision: previousAuthorityRevision,
                    },
                    { $set: authority },
                    options,
                  );
                  if (result.matchedCount !== 1)
                    throw new ConflictException(
                      'Tenant authority changed; reload before saving',
                    );
                }
              }
              await this.collection('configuration').updateOne(
                { environment, tenantId: id },
                { $set: metadata },
                { ...options, upsert: true },
              );
            },
            appendAudit: async (event) => {
              await this.collection('audit').insertOne(event, {
                session,
                maxTimeMS: 3000,
              });
            },
          }),
        {
          readConcern: { level: 'snapshot' },
          writeConcern: { w: 'majority', wtimeoutMS: 5000 },
          readPreference: 'primary',
          maxCommitTimeMS: 5000,
        },
      );
    } catch (error) {
      if ((error as { code?: number }).code === 11000)
        throw new ConflictException(
          'Tenant identity or domain already assigned',
        );
      if ((error as { code?: number }).code === 20)
        throw new ServiceUnavailableException(
          'Explorer writes require MongoDB replica-set transactions',
        );
      throw error;
    } finally {
      await session.endSession();
    }
  }
}
