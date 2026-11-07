import test from 'node:test';
import assert from 'node:assert/strict';
import { explorerSecretsFromV2 } from '../src/v2-bootstrap.js';
test('pins application and tenant memory without constructing legacy Vault clients', async () => {
  const row = (accessName: string, value: string) => ({
    resourceId: accessName,
    versionId: 'v1',
    name: accessName,
    accessName,
    value,
    kind: 'secret' as const,
    valueFormat: 'text' as const,
    schemaIdentity: 'secret:text@1',
  });
  const secrets = explorerSecretsFromV2(
    { VAULT_APPLICATION_ID: 'explorer-api' },
    {
      format: 2,
      applicationId: 'explorer-api',
      environment: 'development',
      revision: 'r1',
      application: {
        ready: true,
        values: [
          row('CLERK_SECRET_KEY', 'app'),
          ...[
            'EXPLORER_MONGODB_URI',
            'WORKFLOW_SHARED_WRAPPING_KEY_V1',
            'EXPLORER_CREDENTIAL_KEY',
            'MANAGER_SETUP_CONTROL_KEY',
          ].map((name) => row(name, 'fixture')),
        ],
      },
      tenants: {
        fcrww: { ready: true, values: [row('CLERK_SECRET_KEY', 'tenant')] },
      },
    },
  );
  assert.equal(secrets.environment.CLERK_SECRET_KEY, 'app');
  assert.equal(
    secrets.secret(
      { environment: 'development', tenantId: 'fcrww', configRevision: 1 },
      'vault:CLERK_SECRET_KEY',
    ),
    'tenant',
  );
  assert.throws(() =>
    secrets.secret(
      { environment: 'development', tenantId: 'other', configRevision: 1 },
      'vault:CLERK_SECRET_KEY',
    ),
  );
  secrets.close();
});
