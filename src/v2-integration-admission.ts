import { BadRequestException } from '@nestjs/common';
import { MongoClient } from 'mongodb';
import { ConnectionString } from 'mongodb-connection-string-url';
import { assertRuntimeDatabase } from '@kick-playr/local-key-vault/runtime-client/integration-runtime';
import type { IntegrationAdmission } from './tenant.service.js';
import type { Definition } from './contracts.js';
import type { ExplorerSecrets } from './secrets.js';

export function createV2IntegrationAdmission(options: {
  integration(definition: Definition, reference: string): { resourceId: string; versionId: string; kind: string; schemaIdentity: string; value: unknown };
  readAuthority(definition: Definition, integrationId: string): Promise<Record<string, unknown> | null>;
}): IntegrationAdmission {
  return async (definition, _id, connection) => {
    const unavailable = () => new BadRequestException('Enabled integrations require an active native runtime authority');
    const resource = options.integration(definition, connection.credentialId);
    const config = resource.value;
    const schema = connection.provider === 'smtp' || connection.provider === 'imap' ? 'email' : connection.provider;
    const identities = ['email', 'pingen'].includes(schema) ? [`builtin:${schema}@1`, `builtin:${schema}@2`] : [`builtin:${schema}@1`];
    if (resource.kind !== 'integration' || !identities.includes(resource.schemaIdentity) || !resource.resourceId || !resource.versionId ||
      !config || typeof config !== 'object' || Array.isArray(config))
      throw unavailable();
    // Static provider credentials remain exclusively in the pinned Vault JSON.
    if (connection.provider === 'smtp' || connection.provider === 'imap') {
      if (!('protocol' in config) || config.protocol !== connection.provider ||
        (connection.provider === 'imap' && (resource.schemaIdentity !== 'builtin:email@2' ||
          !('inboxFolder' in config) || typeof config.inboxFolder !== 'string' || !config.inboxFolder ||
          !('archiveFolder' in config) || typeof config.archiveFolder !== 'string' || !config.archiveFolder)))
        throw new BadRequestException('Email protocol or explicit IMAP folders do not match static configuration');
      return;
    }
    if (connection.provider === 'pingen') {
      const events = connection.capabilities.includes('letters:events');
      const send = connection.capabilities.includes('letters:send');
      const text = (field: string) => field in config && typeof (config as Record<string, unknown>)[field] === 'string' && !!(config as Record<string, unknown>)[field];
      if ((events && (resource.schemaIdentity !== 'builtin:pingen@2' || !text('webhookSecret'))) || ((!events || send) && (!text('apiToken') || !text('organizationId'))))
        throw new BadRequestException('Pingen static configuration does not support the requested capabilities');
      return;
    }
    if (!['bexio', 'dropbox'].includes(connection.provider) ||
      !('accountReference' in config) || config.accountReference !== connection.accountReference)
      throw unavailable();
    const row = await options.readAuthority(definition, resource.resourceId);
    if (!row || row._id !== `${definition.environment}/${resource.resourceId}` ||
      row.tenantId !== definition.id || row.environment !== definition.environment ||
      row.integrationId !== resource.resourceId || row.staticVersion !== resource.versionId ||
      row.accountReference !== connection.accountReference || row.status !== 'active' ||
      row.operation !== null || !Number.isSafeInteger(row.authorityGeneration) ||
      Number(row.authorityGeneration) < 1 || !Number.isSafeInteger(row.revision) || Number(row.revision) < 1)
      throw unavailable();
  };
}

/** Metadata only: Explorer never decrypts, refreshes, or copies runtime credentials. */
export function nativeAuthorityReader(
  secrets: Pick<ExplorerSecrets, 'secret'>,
  open = (uri: string) => new MongoClient(uri, {
    readPreference: 'primary', serverSelectionTimeoutMS: 5000, connectTimeoutMS: 5000, maxPoolSize: 1,
  }),
) {
  return async (definition: Definition, integrationId: string): Promise<Record<string, unknown> | null> => {
    const database = `${definition.id}-kick-playr`;
    assertRuntimeDatabase(database, definition.id);
    if (typeof definition.environment !== 'string' || !/^[a-z][a-z0-9-]{0,31}$/.test(definition.environment))
      throw Error('Invalid tenant runtime environment');
    const uri = secrets.secret({ environment: definition.environment, tenantId: definition.id,
      configRevision: definition.configRevision }, definition.secretReferences.mongoUri);
    const configuredDatabase = decodeURIComponent(new ConnectionString(uri).pathname.slice(1));
    if (configuredDatabase && configuredDatabase !== database) throw Error('Runtime credentials require the tenant database');
    const client = open(uri);
    try {
      await client.connect();
      return await client.db(database).collection('integration_runtime_credentials').findOne({
        _id: `${definition.environment}/${integrationId}` as never,
        tenantId: definition.id, environment: definition.environment, integrationId,
      }, { projection: { _id: 1, tenantId: 1, environment: 1, integrationId: 1,
        staticVersion: 1, accountReference: 1, authorityGeneration: 1, revision: 1, status: 1, operation: 1 } });
    } finally { await client.close(); }
  };
}
