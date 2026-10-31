import { BadRequestException } from '@nestjs/common';

/** Snapshot of concrete club grants used by the operational runtime. Wildcards never reach runtime storage. */
export const tenantPermissionCatalog = [
  'club:actions:oauth:state',
  'club:actions:qr:approve',
  'club:api-keys:revoke',
  'club:audit:append',
  'club:audit:read',
  'club:bills:create',
  'club:bills:read',
  'club:bills:remind',
  'club:bills:send',
  'club:bills:write',
  'club:callbacks:pingen:process',
  'club:catalog:read',
  'club:catalog:write',
  'club:clothes:send',
  'club:contacts:read',
  'club:contacts:write',
  'club:integration-connections:manage',
  'club:integrations:read',
  'club:integrations:use',
  'club:integrations:write',
  'club:jobs:read',
  'club:letters:send',
  'club:mail:send',
  'club:mailbox:resolve',
  'club:matrix-backups:read',
  'club:matrix-backups:write',
  'club:matrix:rooms:read',
  'club:matrix:rooms:write',
  'club:matrix:session:read',
  'club:matrix:sync',
  'club:member-changes:read',
  'club:member-changes:write',
  'club:memberchange:apply',
  'club:membership:render',
  'club:notes:read',
  'club:notifications:read',
  'club:notifications:record',
  'club:notifications:write',
  'club:player-images:issue',
  'club:player-images:read',
  'club:public-links:issue',
  'club:public-links:verify',
  'club:public-rate-limits:consume',
  'club:qr:issue',
  'club:qr:manage',
  'club:qr:use',
  'club:registration:submit',
  'club:reports:read',
  'club:settings:read',
  'club:settings:write',
  'club:tasks:read',
  'club:tasks:write',
  'club:teams:read',
  'club:teams:write',
  'club:trials:read',
  'club:trials:write',
  'club:vacation:read',
  'club:vacation:write',
] as const;

export function expandTenantPermissions(input: readonly string[]): string[] {
  if (
    input.some(
      (p) => p !== 'club:*:*' && !/^club:[a-z][a-z0-9:._-]{0,127}$/.test(p),
    )
  )
    throw new BadRequestException(
      'Only tenant-scoped club permissions can be assigned',
    );
  const permissions = [
    ...new Set(
      input.flatMap((p) =>
        p === 'club:*:*' ? [...tenantPermissionCatalog] : [p],
      ),
    ),
  ];
  if (permissions.length > 128)
    throw new BadRequestException(
      'Expanded tenant permissions exceed the limit of 128',
    );
  return permissions;
}
