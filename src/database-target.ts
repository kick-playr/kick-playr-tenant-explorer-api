import { ConflictException } from '@nestjs/common';
import { createHash } from 'node:crypto';
import { ConnectionString } from 'mongodb-connection-string-url';
import type { ClientSession, MongoClient } from 'mongodb';
export const deletionTargetCollection = 'tenantDeletionTargets';
export function databaseLocation(uri: string, database: string) {
  const parsed = new ConnectionString(uri);
  return JSON.stringify([
    parsed.protocol,
    parsed.hosts.map((host) => host.toLowerCase()).sort(),
    database.toLowerCase(),
  ]);
}
export function databaseTargetId(uri: string, database: string) {
  return createHash('sha256')
    .update(databaseLocation(uri, database))
    .digest('hex');
}
/** Must be called in the SAME transaction as assigning the encrypted runtime binding.
 * Both assignment and purge reservation write this document, making races conflict. */
export async function fenceDatabaseAssignment(
  client: MongoClient,
  controlDatabase: string,
  uri: string,
  database: string,
  session: ClientSession,
) {
  const collection = client
    .db(controlDatabase)
    .collection(deletionTargetCollection);
  const _id = databaseTargetId(uri, database) as never;
  const options = { session, maxTimeMS: 3000 };
  const current = await collection.findOne({ _id }, options);
  if (current?.operationId)
    throw new ConflictException(
      'Database is permanently reserved for tenant deletion',
    );
  await collection.updateOne(
    { _id },
    { $inc: { writeFence: 1 } },
    { ...options, upsert: true },
  );
}
