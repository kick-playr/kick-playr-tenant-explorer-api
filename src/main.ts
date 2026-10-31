import 'dotenv/config';
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
function required(name: string) {
  const value = process.env[name];
  if (!value) throw new Error(`Required environment variable: ${name}`);
  return value;
}
async function bootstrap() {
  const key = required('EXPLORER_CREDENTIAL_KEY');
  if (!/^[a-fA-F0-9]{64}$/.test(key))
    throw new Error('EXPLORER_CREDENTIAL_KEY must be a 64-character hex key');
  const port = Number(process.env.PORT ?? 3003);
  if (!Number.isInteger(port) || port < 1 || port > 65535)
    throw new Error('Invalid PORT');
  const database = required('EXPLORER_CONTROL_DATABASE');
  const rootText = required('WORKFLOW_SHARED_WRAPPING_KEY_V1');
  const rootKey = Buffer.from(rootText, 'base64');
  if (
    rootText.length !== 44 ||
    rootKey.length !== 32 ||
    rootKey.toString('base64') !== rootText
  ) {
    rootKey.fill(0);
    throw Error('Invalid shared configuration bootstrap');
  }
  const client = new MongoClient(required('EXPLORER_MONGODB_URI'), {
    readPreference: 'primary',
    retryReads: true,
    retryWrites: true,
    serverSelectionTimeoutMS: 5000,
    connectTimeoutMS: 5000,
    maxPoolSize: 8,
  });
  let config;
  try {
    await client.connect();
    config = await loadExplorerConfiguration(client, database, rootKey);
  } catch (error) {
    await client.close();
    throw error;
  } finally {
    rootKey.fill(0);
  }
  const vault = new CredentialVault(Buffer.from(key, 'hex'));
  let app: Awaited<ReturnType<typeof createApp>> | undefined;
  try {
    app = await createApp({
      clubRuntime: new ClubRuntime(config.clubRuntimes),
      keyFiles: new KeyFileRegistry(config.keyBindings.bindings, database),
      publicRealms: new PublicRealmDirectory(config),
      repository: new MongoRepository(client, database),
      vault,
      invitations: new InvitationService(
        new MongoInvitationRepository(client, database),
        invitationBindings(
          process.env.EXPLORER_INVITATION_BINDINGS_JSON,
          process.env,
        ),
        new ClerkInvitationIdentity(),
        vault,
        invitationSender(process.env),
      ),
      auth: {
        clubRealms: config.clubRealms,
        issuer: config.issuer,
        authorizedParties: config.authorizedParties,
        adminSubjects: config.adminSubjects,
        secretKey: process.env.CLERK_SECRET_KEY,
      },
    });
    await app.listen(port, process.env.HOST ?? '127.0.0.1');
  } catch (error) {
    await app?.close();
    await client.close();
    throw error;
  }
}
bootstrap().catch(() => {
  console.error(
    'Tenant explorer API startup failed. Check database, Clerk and vault configuration.',
  );
  process.exitCode = 1;
});
