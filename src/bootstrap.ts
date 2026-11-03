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
import { createTenantControllers } from './tenant-live.js';

import { InvitationService } from './invitations/service.js';
import { MongoInvitationRepository } from './invitations/repository.js';
import {
  ClerkInvitationIdentity,
  invitationBindings,
} from './invitations/identity.js';
import { invitationSender } from './invitations/delivery.js';
import { OnboardingService } from './onboarding/service.js';
import { SetupRuntime } from './onboarding/runtime.js';
import { StartupDiagnostics } from './startup-diagnostics.js';
function required(environment: NodeJS.ProcessEnv, name: string) {
  const value = environment[name];
  if (!value) throw new Error(`Required environment variable: ${name}`);
  return value;
}
export async function composeApplication(secrets: ExplorerSecrets, diagnostics = new StartupDiagnostics()) {
  const environment = secrets.environment;
  const { key, port, database, rootText, rootKey, client } = await diagnostics.run('configuration', async () => {
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
    return { key, port, database, rootText, rootKey, client };
  });
  let tenantControllers: Awaited<ReturnType<typeof createTenantControllers>> | undefined;
  try {
    let config: Awaited<ReturnType<typeof loadExplorerConfiguration>>;
    try {
      await diagnostics.run('database.connect', () => client.connect());
      config = await diagnostics.run('database.configuration', () => loadExplorerConfiguration(client, database, rootKey));
      // Only the decrypted database can register finite tenant controllers.
      if (secrets.strategy === 'LOCAL_KEYVAULT') {
        tenantControllers = await diagnostics.run('secrets.tenants', () => createTenantControllers({
          secrets, client, database, wrappingKey: rootKey,
          bindings: config.keyBindings.bindings as import('./secrets.js').SecretKeyBinding[],
        }));
      }
    } catch (error) {
      tenantControllers?.close();
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
      app = await diagnostics.run('application.compose', () => createApp({
        tenantAdmission: tenantControllers?.middleware,
        keyRotationStatus: tenantControllers?.rotationStatus,
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
            tenantControllers?.close();
            runtimeMongo.onModuleDestroy();
            vault.destroy();
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
      }));
      const application = app;
      await diagnostics.run('application.initialize', () => application.init());
      return {
        handler: application.getHttpAdapter().getInstance() as import('node:http').RequestListener,
        close: () => application.close(),
        port,
        host: environment.HOST ?? '127.0.0.1',
      };
    } catch (error) {
      await app?.close();
      tenantControllers?.close();
      runtimeMongo.onModuleDestroy();
      vault.destroy();
      await client.close();
      secrets.close();
      throw error;
    }
  } catch (error) {
    tenantControllers?.close();
    await client.close();
    secrets.close();
    throw error;
  }
}

/** Compatibility entry point: a single listener owns process shutdown. */
export async function bootstrap(secrets: ExplorerSecrets, diagnostics = new StartupDiagnostics()) {
  const application = await composeApplication(secrets, diagnostics);
  const { createServer } = await import('node:http');
  const server = createServer(application.handler);
  try {
    await diagnostics.run('server.listen', () => new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(application.port, application.host, () => { server.off('error', reject); resolve(); });
    }));
  } catch (error) { await application.close(); throw error; }
  const close = () => { server.close(); void application.close(); };
  process.once('SIGINT', close);
  process.once('SIGTERM', close);
}
