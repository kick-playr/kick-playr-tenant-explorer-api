import {
  BadRequestException,
  ConflictException,
  NotFoundException,
} from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import {
  createSchema,
  credentialSchema,
  emptyMetadata,
  environmentSchema,
  grantRevisionSchema,
  identifier,
  integrationSchema,
  listSchema,
  normalizeHost,
  parse,
  revisionSchema,
  updateSchema,
  userSchema,
  type Aggregate,
  type Definition,
  type TenantView,
  type UserGrant,
} from './contracts.js';
import type { Repository } from './repository.js';
import { CredentialVault } from './vault.js';
import { KeyFileRegistry } from './key-files.js';
import { expandTenantPermissions } from './tenant-permissions.js';

export class TenantService {
  constructor(
    private readonly repository: Repository,
    private readonly vault: CredentialVault,
    private readonly keyFileRegistry = new KeyFileRegistry(),
    private readonly secretsStrategy:
      'ENV_VARIABLES' | 'LOCAL_KEYVAULT' = 'ENV_VARIABLES',
  ) {}
  private key(environment: string, id: string) {
    parse(environmentSchema, environment);
    parse(identifier, id);
  }
  private definitionView(d: Definition): Definition {
    return {
      id: d.id,
      environment: d.environment,
      hostname: d.hostname,
      aliases: [...d.aliases],
      status: d.status,
      ...(d.deletionId ? { deletionId: d.deletionId } : {}),
      configRevision: d.configRevision,
      public: { name: d.public.name, locale: d.public.locale },
      secretReferences: {
        mongoUri: d.secretReferences.mongoUri,
        key: d.secretReferences.key,
      },
    };
  }
  private view(a: Aggregate): TenantView {
    return {
      ...this.definitionView(a.definition),
      identityRealm: a.authority?.identityRealm ?? '',
      authorityRevision: a.authority?.authorityRevision ?? 0,
      configuration: a.metadata.configuration,
      integrations: a.metadata.integrations,
      credentials: a.metadata.credentials.map((c) => ({
        id: c.id,
        label: c.label,
        status: c.status,
        revision: c.revision,
        updatedAt: c.updatedAt,
      })),
      users: (a.authority?.users ?? []).map((u) => ({
        issuer: u.issuer,
        subject: u.subject,
        revision: u.revision,
        status: u.status,
        contactId: u.contactId,
        permissions: [...u.permissions],
      })),
    };
  }
  async list(query: unknown) {
    const result = await this.repository.list(parse(listSchema, query));
    return {
      ...result,
      items: result.items.map((d) => this.definitionView(d)),
    };
  }
  async get(environment: string, id: string) {
    this.key(environment, id);
    const a = await this.repository.read(environment, id);
    if (!a) throw new NotFoundException('Tenant not found');
    return this.view(a);
  }
  async audit(environment: string, id: string) {
    await this.get(environment, id);
    return this.repository.audit(environment, id);
  }
  async keyFiles(environment: string, id: string) {
    this.key(environment, id);
    const aggregate = await this.repository.read(environment, id);
    if (!aggregate) throw new NotFoundException('Tenant not found');
    return this.keyFileRegistry.describe(aggregate.definition);
  }
  private hosts(d: Definition) {
    d.hostname = normalizeHost(d.hostname, d.environment);
    d.aliases = d.aliases.map((h) => normalizeHost(h, d.environment));
    if (new Set([d.hostname, ...d.aliases]).size !== d.aliases.length + 1)
      throw new BadRequestException('Duplicate tenant hostname or alias');
  }
  async create(body: unknown, actor: string) {
    const input = parse(createSchema, body);
    const { identityRealm, ...fields } = input;
    const definition: Definition = {
      ...fields,
      configRevision: 1,
      status: 'provisioning',
    };
    this.hosts(definition);
    return this.repository.transaction(async (tx) => {
      if (await tx.read(definition.environment, definition.id))
        throw new ConflictException('Tenant already exists');
      const aggregate: Aggregate = {
        definition,
        metadata: emptyMetadata(),
        authority: {
          schema: 1,
          tenantId: definition.id,
          environment: definition.environment,
          configRevision: 1,
          authorityRevision: 1,
          supportRevision: 1,
          status: 'disabled',
          identityRealm,
          hostnames: [definition.hostname, ...definition.aliases],
          users: [],
          services: [],
        },
      };
      await tx.save(aggregate, null);
      await tx.appendAudit({
        id: randomUUID(),
        environment: definition.environment,
        tenantId: definition.id,
        action: 'tenant.created',
        actor,
        revision: 1,
        at: new Date().toISOString(),
      });
      return this.view(aggregate);
    });
  }
  private async mutate(
    environment: string,
    id: string,
    expected: number,
    actor: string,
    action: string,
    edit: (a: Aggregate) => void,
    resource?: string,
    expectedAuthorityRevision?: number,
  ) {
    this.key(environment, id);
    return this.repository.transaction(async (tx) => {
      const aggregate = await tx.read(environment, id);
      if (!aggregate) throw new NotFoundException('Tenant not found');
      if (aggregate.definition.deletionId)
        throw new ConflictException(
          'Tenant is marked for deletion; use the deletion workflow',
        );
      if (aggregate.definition.configRevision !== expected)
        throw new ConflictException('Tenant changed; reload before saving');
      if (
        expectedAuthorityRevision !== undefined &&
        aggregate.authority?.authorityRevision !== expectedAuthorityRevision
      )
        throw new ConflictException(
          'Tenant user access changed; reload before saving',
        );
      if (
        expected >= Number.MAX_SAFE_INTEGER - 1 ||
        (aggregate.authority?.authorityRevision ?? 0) >=
          Number.MAX_SAFE_INTEGER - 1
      )
        throw new ConflictException('Tenant revision exhausted');
      edit(aggregate);
      this.hosts(aggregate.definition);
      // Grant generations revoke access without rebinding encrypted club data.
      if (expectedAuthorityRevision === undefined)
        aggregate.definition.configRevision++;
      const authority = aggregate.authority;
      if (!authority)
        throw new BadRequestException(
          'Configure an identity realm before maintaining this tenant',
        );
      authority.configRevision = aggregate.definition.configRevision;
      authority.authorityRevision++;
      authority.supportRevision = (authority.supportRevision ?? 0) + 1;
      authority.status =
        aggregate.definition.status === 'provisioning'
          ? 'disabled'
          : aggregate.definition.status;
      authority.hostnames = [
        aggregate.definition.hostname,
        ...aggregate.definition.aliases,
      ];
      await tx.save(aggregate, expected);
      await tx.appendAudit({
        id: randomUUID(),
        environment,
        tenantId: id,
        action,
        actor,
        revision: aggregate.definition.configRevision,
        ...(resource ? { resource } : {}),
        at: new Date().toISOString(),
      });
      return this.view(aggregate);
    });
  }
  async update(environment: string, id: string, body: unknown, actor: string) {
    const { expectedRevision, identityRealm, configuration, ...fields } = parse(
      updateSchema,
      body,
    );
    return this.mutate(
      environment,
      id,
      expectedRevision,
      actor,
      'tenant.updated',
      (a) => {
        Object.assign(a.definition, fields);
        if (identityRealm) {
          if (
            a.authority &&
            identityRealm !== a.authority.identityRealm &&
            a.authority.users.length > 0
          )
            throw new ConflictException(
              'Identity realm changes with retained user grants require an explicit migration',
            );
          a.authority ??= {
            schema: 1,
            tenantId: id,
            environment,
            configRevision: expectedRevision,
            authorityRevision: 0,
            status: 'disabled',
            identityRealm,
            hostnames: [],
            users: [],
            services: [],
          };
          a.authority.identityRealm = identityRealm;
        }
        if (configuration) a.metadata.configuration = configuration;
      },
    );
  }
  async putUser(
    environment: string,
    id: string,
    subject: string,
    body: unknown,
    actor: string,
  ) {
    const { expectedRevision, expectedAuthorityRevision, ...user } = parse(
      userSchema,
      body,
    );
    user.permissions = expandTenantPermissions(user.permissions);
    if (subject !== user.subject)
      throw new BadRequestException('User subject must match route');
    return this.mutate(
      environment,
      id,
      expectedRevision,
      actor,
      'user.updated',
      (a) => {
        if (!a.authority || a.authority.identityRealm !== user.issuer)
          throw new BadRequestException(
            'User issuer must match tenant identity realm',
          );
        const index = a.authority.users.findIndex(
          (u) => u.subject === subject && u.issuer === user.issuer,
        );
        if (index < 0 && a.authority.users.length >= 128)
          throw new BadRequestException('Tenant user limit reached');
        const grant: UserGrant = {
          ...user,
          revision: index >= 0 ? a.authority.users[index]!.revision + 1 : 1,
        };
        if (index >= 0) a.authority.users[index] = grant;
        else a.authority.users.push(grant);
      },
      subject,
      expectedAuthorityRevision ?? expectedRevision,
    );
  }
  async revokeUser(
    environment: string,
    id: string,
    subject: string,
    body: unknown,
    actor: string,
  ) {
    const { expectedRevision, expectedAuthorityRevision } = parse(
      grantRevisionSchema,
      body,
    );
    return this.mutate(
      environment,
      id,
      expectedRevision,
      actor,
      'user.revoked',
      (a) => {
        const user = a.authority?.users.find(
          (u) =>
            u.subject === subject && u.issuer === a.authority!.identityRealm,
        );
        if (!user) throw new NotFoundException('Tenant user not found');
        user.status = 'revoked';
        user.revision++;
      },
      subject,
      expectedAuthorityRevision ?? expectedRevision,
    );
  }
  async putCredential(
    environment: string,
    id: string,
    credentialId: string,
    body: unknown,
    actor: string,
  ) {
    parse(identifier, credentialId);
    if (this.secretsStrategy === 'LOCAL_KEYVAULT')
      throw new BadRequestException(
        'Store credentials in the vault through the authorized provisioning workflow',
      );
    const { expectedRevision, label, value } = parse(credentialSchema, body);
    return this.mutate(
      environment,
      id,
      expectedRevision,
      actor,
      'credential.replaced',
      (a) => {
        if (
          a.metadata.integrations.some(
            (c) => c.enabled && c.credentialId === credentialId,
          )
        )
          throw new ConflictException(
            'Disable linked integrations before replacing this credential',
          );
        const existing = a.metadata.credentials.find(
          (c) => c.id === credentialId,
        );
        if (!existing && a.metadata.credentials.length >= 128)
          throw new BadRequestException('Tenant credential limit reached');
        const record = {
          id: credentialId,
          label,
          status: 'active' as const,
          revision: (existing?.revision ?? 0) + 1,
          updatedAt: new Date().toISOString(),
          envelope: this.vault.seal(
            `${environment}/${id}/${credentialId}`,
            value,
          ),
        };
        a.metadata.credentials = [
          ...a.metadata.credentials.filter((c) => c.id !== credentialId),
          record,
        ];
      },
      credentialId,
    );
  }
  async revokeCredential(
    environment: string,
    id: string,
    credentialId: string,
    body: unknown,
    actor: string,
  ) {
    parse(identifier, credentialId);
    const { expectedRevision } = parse(revisionSchema, body);
    return this.mutate(
      environment,
      id,
      expectedRevision,
      actor,
      'credential.revoked',
      (a) => {
        if (
          a.metadata.integrations.some(
            (c) => c.enabled && c.credentialId === credentialId,
          )
        )
          throw new ConflictException(
            'Disable linked integrations before revoking this credential',
          );
        const credential = a.metadata.credentials.find(
          (c) => c.id === credentialId,
        );
        if (!credential) throw new NotFoundException('Credential not found');
        credential.status = 'revoked';
        credential.revision++;
        credential.updatedAt = new Date().toISOString();
        delete credential.envelope;
      },
      credentialId,
    );
  }
  async putIntegration(
    environment: string,
    id: string,
    connectionId: string,
    body: unknown,
    actor: string,
  ) {
    parse(identifier, connectionId);
    const { expectedRevision, ...connection } = parse(integrationSchema, body);
    return this.mutate(
      environment,
      id,
      expectedRevision,
      actor,
      'integration.updated',
      (a) => {
        if (
          connection.enabled &&
          !a.metadata.credentials.some(
            (c) => c.id === connection.credentialId && c.status === 'active',
          )
        )
          throw new BadRequestException(
            'Enabled integrations require an active credential',
          );
        if (
          !a.metadata.integrations.some((c) => c.id === connectionId) &&
          a.metadata.integrations.length >= 64
        )
          throw new BadRequestException('Tenant integration limit reached');
        a.metadata.integrations = [
          ...a.metadata.integrations.filter((c) => c.id !== connectionId),
          {
            id: connectionId,
            ...connection,
            updatedAt: new Date().toISOString(),
          },
        ];
      },
      connectionId,
    );
  }
  async removeIntegration(
    environment: string,
    id: string,
    connectionId: string,
    body: unknown,
    actor: string,
  ) {
    parse(identifier, connectionId);
    const { expectedRevision } = parse(revisionSchema, body);
    return this.mutate(
      environment,
      id,
      expectedRevision,
      actor,
      'integration.removed',
      (a) => {
        const connection = a.metadata.integrations.find(
          (c) => c.id === connectionId,
        );
        if (!connection) throw new NotFoundException('Integration not found');
        if (connection.enabled)
          throw new ConflictException(
            'Disable this integration before removing it',
          );
        a.metadata.integrations = a.metadata.integrations.filter(
          (c) => c.id !== connectionId,
        );
      },
      connectionId,
    );
  }
}
