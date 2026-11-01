import type { ExplorerSecrets } from './secrets.js';
import { DeletionInventoryResolver } from './deletion/inventory.js';
import { DeletionService } from './deletion/service.js';
import { MongoDeletionStore, MongoPurgePort } from './deletion/mongo.js';
import { RuntimeMongoService } from './runtime-mongo.js';
import { createApp } from './app.js';
import { MongoRepository } from './repository.js';
import { CredentialVault } from './vault.js';
import { MongoClient } from 'mongodb';
import { KeyFileRegistry } from './key-files.js';
import { ClubRuntime } from './club-runtime.js';
import { loadExplorerConfiguration } from './database-config.js';
import { PublicRealmDirectory } from './public-realms.js';

import { InvitationService } from './invitations/service.js';
import { MongoInvitationRepository } from './invitations/repository.js';
import {
  ClerkInvitationIdentity,
  invitationBindings,
} from './invitations/identity.js';
import { invitationSender } from './invitations/delivery.js';
import { OnboardingService } from './onboarding/service.js';
import { SetupRuntime } from './onboarding/runtime.js';
function required(environment: NodeJS.ProcessEnv, name: string) {
  const value = environment[name];
  if (!value) throw new Error(`Required environment variable: ${name}`);
  return value;
}
export async function bootstrap(secrets: ExplorerSecrets) {
  const environment = secrets.environment;
  const key = required(environment, 'EXPLORER_CREDENTIAL_KEY');
  if (!/^[a-fA-F0-9]{64}$/.test(key))
    throw new Error('EXPLORER_CREDENTIAL_KEY must be a 64-character hex key');
  const port = Number(environment.PORT ?? 3003);
  if (!Number.isInteger(port) || port < 1 || port > 65535)
    throw new Error('Invalid PORT');
  const database = required(environment, 'EXPLORER_CONTROL_DATABASE');
  const rootText = required(environment, 'WORKFLOW_SHARED_WRAPPING_KEY_V1');
  const rootKey = Buffer.from(rootText, 'base64');
  if (
    rootText.length !== 44 ||
    rootKey.length !== 32 ||
    rootKey.toString('base64') !== rootText
  ) {
    rootKey.fill(0);
    throw Error('Invalid shared configuration bootstrap');
  }
  const client = new MongoClient(
    required(environment, 'EXPLORER_MONGODB_URI'),
    {
      readPreference: 'primary',
      retryReads: true,
      retryWrites: true,
      serverSelectionTimeoutMS: 5000,
      connectTimeoutMS: 5000,
      maxPoolSize: 8,
    },
  );
  try {
    let config;
    try {
      await client.connect();
      config = await loadExplorerConfiguration(client, database, rootKey);
      // The decrypted database chooses the finite tenant set. No HTTP input or env
      // discovery creates an operational binding. A new revision requires restart.
      if (secrets.strategy === 'LOCAL_KEYVAULT') {
        const bindings = config.keyBindings.bindings as {
          tenantId: string;
          environment: string;
        }[];
        const seen = new Set<string>();
        for (const binding of bindings) {
          const id = `${binding.environment}/${binding.tenantId}`;
          if (seen.has(id)) continue;
          seen.add(id);
          const definition = await client
            .db(database)
            .collection('tenantDefinitions')
            .findOne(
              { id: binding.tenantId, environment: binding.environment },
              { maxTimeMS: 3000 },
            );
          if (!definition || !Number.isSafeInteger(definition.configRevision))
            throw Error('Tenant secrets unavailable');
          await secrets.initializeTenant({
            environment: binding.environment,
            tenantId: binding.tenantId,
            configRevision: definition.configRevision,
          });
        }
      }
    } catch (error) {
      await client.close();
      secrets.close();
      throw error;
    } finally {
      rootKey.fill(0);
    }
    const vault = new CredentialVault(Buffer.from(key, 'hex'));
    const invitationRepository = new MongoInvitationRepository(
        client,
        database,
      ),
      identity = new ClerkInvitationIdentity(),
      bindings = invitationBindings(
        environment.EXPLORER_INVITATION_BINDINGS_JSON,
        environment,
      );
    const sender = invitationSender(environment);
    const setupRuntime = new SetupRuntime(
      config.setupRuntimes ?? config.clubRuntimes,
      environment.MANAGER_SETUP_CONTROL_KEY,
    );
    const runtimeMongo = new RuntimeMongoService(
      client,
      database,
      Buffer.from(rootText, 'base64'),
      required(environment, 'EXPLORER_MONGODB_URI'),
      environment,
      setupRuntime,
      secrets,
    );
    const onboarding = new OnboardingService(
      invitationRepository,
      bindings,
      identity,
      setupRuntime,
      sender,
    );
    let app: Awaited<ReturnType<typeof createApp>> | undefined;
    try {
      const deletionKey = Buffer.from(rootText, 'base64');
      const deletionInventory = new DeletionInventoryResolver(
        client,
        database,
        deletionKey,
        vault,
        secrets.strategy,
      );
      const purger = new MongoPurgePort(
        client,
        database,
        deletionKey,
        deletionInventory,
      );
      app = await createApp({
        deletion: new DeletionService(
          new MongoDeletionStore(
            client,
            database,
            deletionKey,
            deletionInventory,
          ),
          purger,
        ),
        clubRuntime: new ClubRuntime(config.clubRuntimes),
        keyFiles: new KeyFileRegistry(
          config.keyBindings.bindings,
          database,
          environment,
          () => runtimeMongo.loadKeyBindings(),
          secrets,
        ),
        publicRealms: new PublicRealmDirectory(config),
        repository: new MongoRepository(client, database),
        vault,
        secretsStrategy: secrets.strategy,
        shutdown: {
          onModuleDestroy: async () => {
            runtimeMongo.onModuleDestroy();
            secrets.close();
            deletionKey.fill(0);
            await client.close();
          },
        },
        onboarding,
        runtimeMongo,
        invitations: new InvitationService(
          invitationRepository,
          bindings,
          identity,
          vault,
          sender,
          (scope) => onboarding.assertProvisioned(scope),
        ),
        auth: {
          clubRealms: config.clubRealms,
          issuer: config.issuer,
          authorizedParties: config.authorizedParties,
          adminSubjects: config.adminSubjects,
          secretKey: environment.CLERK_SECRET_KEY,
        },
      });
      app.enableShutdownHooks(['SIGTERM', 'SIGINT']);
      await app.listen(port, environment.HOST ?? '127.0.0.1');
    } catch (error) {
      await app?.close();
      runtimeMongo.onModuleDestroy();
      await client.close();
      secrets.close();
      throw error;
    }
  } catch (error) {
    await client.close();
    secrets.close();
    throw error;
  }
}
