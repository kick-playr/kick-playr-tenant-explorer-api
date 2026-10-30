import {
  Body,
  Controller,
  Delete,
  Get,
  Inject,
  Param,
  Patch,
  Post,
  Put,
  Query,
  Req,
  UseGuards,
} from '@nestjs/common';
import { ApiBearerAuth, ApiBody, ApiOperation, ApiTags } from '@nestjs/swagger';
import { PlatformGuard, type PlatformRequest } from './auth.js';
import { TenantService } from './tenant.service.js';

const revisionBody = {
  type: 'object' as const,
  required: ['expectedRevision'],
  properties: { expectedRevision: { type: 'integer' as const, minimum: 1 } },
};
@ApiTags('Platform tenants')
@ApiBearerAuth()
@UseGuards(PlatformGuard)
@Controller('api/platform/tenants')
export class TenantController {
  constructor(@Inject(TenantService) private readonly service: TenantService) {}
  @Get(':environment/:id/keys')
  @ApiOperation({
    summary:
      'Inspect configured tenant key files; returns paths, availability and SHA-256 fingerprints, never key values',
  })
  keys(@Param('environment') environment: string, @Param('id') id: string) {
    return this.service.keyFiles(environment, id);
  }
  @Get()
  @ApiOperation({
    summary: 'Search and paginate all tenants by environment and status',
  })
  list(@Query() query: Record<string, string>) {
    return this.service.list(query);
  }
  @Post()
  @ApiOperation({
    summary: 'Create a provisioning tenant and its control-plane authority',
  })
  @ApiBody({
    schema: {
      type: 'object',
      required: [
        'id',
        'environment',
        'hostname',
        'aliases',
        'public',
        'secretReferences',
        'identityRealm',
      ],
      example: {
        id: 'my-club',
        environment: 'development',
        hostname: 'my-club.localhost:4311',
        aliases: [],
        public: { name: 'My club', locale: 'de-CH' },
        secretReferences: {
          mongoUri: 'local:my-club:mongo',
          key: 'local:my-club:key',
        },
        identityRealm: 'https://example.clerk.accounts.dev',
      },
    },
  })
  create(@Body() body: unknown, @Req() req: PlatformRequest) {
    return this.service.create(body, req.platformSubject);
  }
  @Get(':environment/:id')
  @ApiOperation({
    summary: 'Read a tenant; credential values are never returned',
  })
  get(@Param('environment') environment: string, @Param('id') id: string) {
    return this.service.get(environment, id);
  }
  @Patch(':environment/:id')
  @ApiOperation({
    summary:
      'Update tenant domains, lifecycle and non-secret configuration with a revision check',
  })
  @ApiBody({
    schema: {
      ...revisionBody,
      example: { expectedRevision: 1, status: 'active' },
    },
  })
  update(
    @Param('environment') environment: string,
    @Param('id') id: string,
    @Body() body: unknown,
    @Req() req: PlatformRequest,
  ) {
    return this.service.update(environment, id, body, req.platformSubject);
  }
  @Get(':environment/:id/audit')
  @ApiOperation({ summary: 'Read the latest 100 administrative audit events' })
  audit(@Param('environment') environment: string, @Param('id') id: string) {
    return this.service.audit(environment, id);
  }
  @Put(':environment/:id/users/:subject')
  @ApiOperation({ summary: 'Create or update a Clerk identity tenant grant' })
  @ApiBody({
    schema: {
      ...revisionBody,
      example: {
        expectedRevision: 1,
        issuer: 'https://example.clerk.accounts.dev',
        subject: 'user_example',
        contactId: 23,
        status: 'active',
        permissions: ['club:teams:read'],
      },
    },
  })
  user(
    @Param('environment') environment: string,
    @Param('id') id: string,
    @Param('subject') subject: string,
    @Body() body: unknown,
    @Req() req: PlatformRequest,
  ) {
    return this.service.putUser(
      environment,
      id,
      subject,
      body,
      req.platformSubject,
    );
  }
  @Delete(':environment/:id/users/:subject')
  @ApiOperation({
    summary: 'Revoke a tenant user grant and increment its generation',
  })
  @ApiBody({ schema: revisionBody })
  revokeUser(
    @Param('environment') environment: string,
    @Param('id') id: string,
    @Param('subject') subject: string,
    @Body() body: unknown,
    @Req() req: PlatformRequest,
  ) {
    return this.service.revokeUser(
      environment,
      id,
      subject,
      body,
      req.platformSubject,
    );
  }
  @Put(':environment/:id/integrations/:connectionId')
  @ApiOperation({
    summary:
      'Maintain explorer integration configuration (does not activate provider runtime)',
  })
  @ApiBody({
    schema: {
      ...revisionBody,
      example: {
        expectedRevision: 1,
        provider: 'smtp',
        label: 'Club mail',
        accountReference: 'mailbox-1',
        capabilities: ['mail:send'],
        credentialId: 'smtp-primary',
        enabled: false,
      },
    },
  })
  integration(
    @Param('environment') environment: string,
    @Param('id') id: string,
    @Param('connectionId') connectionId: string,
    @Body() body: unknown,
    @Req() req: PlatformRequest,
  ) {
    return this.service.putIntegration(
      environment,
      id,
      connectionId,
      body,
      req.platformSubject,
    );
  }
  @Delete(':environment/:id/integrations/:connectionId')
  @ApiOperation({
    summary: 'Remove a disabled explorer integration configuration',
  })
  @ApiBody({ schema: revisionBody })
  removeIntegration(
    @Param('environment') environment: string,
    @Param('id') id: string,
    @Param('connectionId') connectionId: string,
    @Body() body: unknown,
    @Req() req: PlatformRequest,
  ) {
    return this.service.removeIntegration(
      environment,
      id,
      connectionId,
      body,
      req.platformSubject,
    );
  }
  @Put(':environment/:id/credentials/:credentialId')
  @ApiOperation({
    summary:
      'Write or replace an encrypted credential; plaintext is never returned',
  })
  @ApiBody({
    schema: {
      ...revisionBody,
      example: {
        expectedRevision: 1,
        label: 'Club mail password',
        value: 'write-only-value',
      },
    },
  })
  credential(
    @Param('environment') environment: string,
    @Param('id') id: string,
    @Param('credentialId') credentialId: string,
    @Body() body: unknown,
    @Req() req: PlatformRequest,
  ) {
    return this.service.putCredential(
      environment,
      id,
      credentialId,
      body,
      req.platformSubject,
    );
  }
  @Delete(':environment/:id/credentials/:credentialId')
  @ApiOperation({
    summary: 'Revoke a credential and remove the encrypted value',
  })
  @ApiBody({ schema: revisionBody })
  revokeCredential(
    @Param('environment') environment: string,
    @Param('id') id: string,
    @Param('credentialId') credentialId: string,
    @Body() body: unknown,
    @Req() req: PlatformRequest,
  ) {
    return this.service.revokeCredential(
      environment,
      id,
      credentialId,
      body,
      req.platformSubject,
    );
  }
}
