import { ForbiddenException } from '@nestjs/common';
import type { MongoClient } from 'mongodb';
import type {
  InvitationRepository,
  InvitationState,
  InvitationTransaction,
  Scope,
} from './types.js';
/** One document per tenant; built-in _id uniqueness, no startup index/migration. */
export class MongoInvitationRepository implements InvitationRepository {
  constructor(
    private readonly client: MongoClient,
    private readonly database: string,
  ) {}
  async transact<T>(
    s: Scope,
    work: (tx: InvitationTransaction) => Promise<T>,
  ): Promise<T> {
    if (
      !['development', 'test', 'preview', 'production'].includes(
        s.environment,
      ) ||
      !/^[a-z0-9][a-z0-9-]{0,63}$/.test(s.tenantId)
    )
      throw new ForbiddenException('Invalid tenant scope');
    const session = this.client.startSession();
    try {
      return await session.withTransaction(
        async () => {
          const db = this.client.db(this.database),
            opts = { session, maxTimeMS: 3000 };
          const definition = await db
            .collection('tenantDefinitions')
            .findOne({ environment: s.environment, id: s.tenantId }, opts);
          const authority = await db
            .collection('tenantRuntimeAuthorities')
            .findOne(
              { environment: s.environment, tenantId: s.tenantId },
              opts,
            );
          if (
            !definition ||
            !authority ||
            definition.configRevision !== authority.configRevision
          )
            throw new ForbiddenException('Tenant unavailable');
          // Write fence serializes invitation changes with concurrent tenant lifecycle/realm changes.
          const fenced = await db.collection('tenantDefinitions').updateOne(
            {
              environment: s.environment,
              id: s.tenantId,
              configRevision: definition.configRevision,
            },
            { $inc: { invitationFence: 1 } },
            opts,
          );
          if (fenced.matchedCount !== 1)
            throw new ForbiddenException('Tenant changed');
          const collection = db.collection<InvitationState & { _id: string }>(
              'tenantManagerInvitations',
            ),
            key = `${s.environment}/${s.tenantId}`;
          const stored = await collection.findOne({ _id: key }, opts),
            state: InvitationState = stored
              ? structuredClone(stored)
              : { revision: 0, invitations: [], principals: [] };
          const before = JSON.stringify(state);
          const value = await work({
            tenant: {
              definition:
                definition as unknown as InvitationTransaction['tenant']['definition'],
              authority: authority as unknown as NonNullable<
                InvitationTransaction['tenant']['authority']
              >,
            },
            state,
            revokeRuntime: async (issuer, subject) => {
              if (
                !Number.isSafeInteger(authority.authorityRevision) ||
                authority.authorityRevision >= Number.MAX_SAFE_INTEGER - 1
              )
                throw new ForbiddenException('Runtime authority unavailable');
              const result = await db
                .collection('tenantRuntimeAuthorities')
                .updateOne(
                  {
                    environment: s.environment,
                    tenantId: s.tenantId,
                    authorityRevision: authority.authorityRevision,
                  },
                  {
                    $set: { 'users.$[user].status': 'revoked' },
                    $inc: {
                      'users.$[user].revision': 1,
                      authorityRevision: 1,
                      supportRevision: 1,
                    },
                  },
                  {
                    ...opts,
                    arrayFilters: [
                      { 'user.issuer': issuer, 'user.subject': subject },
                    ],
                  },
                );
              if (result.matchedCount !== 1)
                throw new ForbiddenException('Runtime authority changed');
            },
          });
          if (before !== JSON.stringify(state)) {
            state.revision++;
            await collection.replaceOne({ _id: key }, state, {
              ...opts,
              upsert: true,
            });
            await db.collection('tenantExplorerAudit').insertOne(
              {
                environment: s.environment,
                tenantId: s.tenantId,
                id: crypto.randomUUID(),
                action: state.lastEvent?.action ?? 'invitations.changed',
                actor: state.lastEvent?.actor ?? 'invitation-service',
                resource: state.lastEvent?.resource,
                revision: state.revision,
                at: new Date().toISOString(),
              },
              opts,
            );
          }
          return value;
        },
        {
          readConcern: { level: 'snapshot' },
          writeConcern: { w: 'majority', wtimeoutMS: 5000 },
          readPreference: 'primary',
        },
      );
    } finally {
      await session.endSession();
    }
  }
}
