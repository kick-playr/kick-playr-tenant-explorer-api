import 'dotenv/config';
import { createApp } from './app.js';
import { MongoRepository } from './repository.js';
import { CredentialVault } from './vault.js';
import { MongoClient } from 'mongodb';
import { KeyFileRegistry } from './key-files.js';

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
  const app = await createApp({
    keyFiles: await KeyFileRegistry.load(
      process.env.EXPLORER_KEY_BINDINGS_FILE,
      required('EXPLORER_CONTROL_DATABASE'),
    ),
    repository: new MongoRepository(
      new MongoClient(required('EXPLORER_MONGODB_URI'), {
        readPreference: 'primary',
        retryReads: true,
        retryWrites: true,
        serverSelectionTimeoutMS: 5000,
        connectTimeoutMS: 5000,
        maxPoolSize: 8,
      }),
      required('EXPLORER_CONTROL_DATABASE'),
    ),
    vault: new CredentialVault(Buffer.from(key, 'hex')),
    auth: {
      issuer: required('CLERK_ISSUER'),
      authorizedParties: required('EXPLORER_AUTHORIZED_PARTIES')
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean),
      adminSubjects: required('EXPLORER_ADMIN_SUBJECTS')
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean),
      jwtKey: process.env.CLERK_JWT_KEY?.replace(/\\n/g, '\n'),
      secretKey: process.env.CLERK_SECRET_KEY,
    },
  });
  await app.listen(port, process.env.HOST ?? '127.0.0.1');
}
bootstrap().catch(() => {
  console.error(
    'Tenant explorer API startup failed. Check database, Clerk and vault configuration.',
  );
  process.exitCode = 1;
});
