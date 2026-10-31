import { isCatalogMappingRoute } from './catalog-policy.js';
import {
  BadRequestException,
  ForbiddenException,
  Body,
  Controller,
  Get,
  Inject,
  Param,
  Patch,
  Post,
  Put,
  Req,
  UseGuards,
} from '@nestjs/common';
import {
  AUTH_OPTIONS,
  ExplorerSessionGuard,
  type PlatformAuthOptions,
  type PlatformRequest,
} from './auth.js';
import { ClubAccess } from './club-access.js';
import { ClubRuntime } from './club-runtime.js';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';

@UseGuards(ExplorerSessionGuard)
@ApiBearerAuth()
@ApiTags('Explorer access')
@Controller('api/explorer')
export class ExplorerAccessController {
  constructor(
    @Inject(AUTH_OPTIONS) private readonly auth: PlatformAuthOptions,
    @Inject(ClubAccess) private readonly clubs: ClubAccess,
  ) {}
  @Get('access') async access(@Req() req: PlatformRequest) {
    if (
      req.explorerSession.issuer === this.auth.issuer &&
      this.auth.adminSubjects.includes(req.explorerSession.subject)
    ) {
      try {
        return {
          role: 'platform-admin',
          ...(await this.clubs.list(req.explorerSession)),
        };
      } catch (error) {
        if (!(error instanceof ForbiddenException)) throw error;
        return { role: 'platform-admin' };
      }
    }
    return {
      role: 'club-admin',
      ...(await this.clubs.list(req.explorerSession)),
    };
  }
}
@UseGuards(ExplorerSessionGuard)
@ApiBearerAuth()
@ApiTags('Club administration')
@Controller('api/club/tenants')
export class ClubController {
  constructor(
    @Inject(ClubAccess) private readonly clubs: ClubAccess,
    @Inject(ClubRuntime) private readonly runtime: ClubRuntime,
  ) {}
  @Get() list(@Req() req: PlatformRequest) {
    if (Object.keys(req.query).length)
      throw new BadRequestException('Club discovery does not accept filters');
    return this.clubs.list(req.explorerSession);
  }
  private async forward(
    req: PlatformRequest,
    environment: string,
    id: string,
    method: string,
    path: string,
    body?: unknown,
  ) {
    if (Object.keys(req.query).length)
      throw new BadRequestException(
        'Club settings do not accept query parameters',
      );
    const tenant = await this.clubs.require(
      environment,
      id,
      req.explorerSession,
    );
    const write = method !== 'GET' || path.endsWith('/signin');
    if (write)
      await this.clubs.audit(
        tenant,
        req.explorerSession,
        'club.settings.intent',
      );
    const result = await this.runtime.request(
      tenant,
      req.explorerSession,
      method,
      path,
      body,
    );
    if (write)
      await this.clubs.audit(
        tenant,
        req.explorerSession,
        'club.settings.completed',
      );
    return result;
  }
  @Get(':environment/:id/branding') branding(
    @Req() r: PlatformRequest,
    @Param('environment') e: string,
    @Param('id') id: string,
  ) {
    return this.forward(r, e, id, 'GET', '/api/settings/branding');
  }
  @Get(':environment/:id/settings') settings(
    @Req() r: PlatformRequest,
    @Param('environment') e: string,
    @Param('id') id: string,
  ) {
    return this.forward(r, e, id, 'GET', '/api/settings');
  }
  @Patch(':environment/:id/settings') update(
    @Req() r: PlatformRequest,
    @Param('environment') e: string,
    @Param('id') id: string,
    @Body() body: unknown,
  ) {
    return this.forward(r, e, id, 'PATCH', '/api/settings', body);
  }
  @Get(':environment/:id/catalog/:collection') catalog(
    @Req() r: PlatformRequest,
    @Param('environment') e: string,
    @Param('id') id: string,
    @Param('collection') collection: string,
  ) {
    if (!['categories', 'branches'].includes(collection))
      throw new BadRequestException('Invalid catalog');
    return this.forward(r, e, id, 'GET', `/api/settings/catalog/${collection}`);
  }
  @Put(':environment/:id/catalog/:collection/flags/:flag') catalogFlag(
    @Req() r: PlatformRequest,
    @Param('environment') e: string,
    @Param('id') id: string,
    @Param('collection') collection: string,
    @Param('flag') flag: string,
    @Body() body: unknown,
  ) {
    if (
      !isCatalogMappingRoute(
        'PUT',
        `/api/settings/catalog/${collection}/flags/${flag}`,
      )
    )
      throw new BadRequestException('Invalid catalog mapping');
    return this.forward(
      r,
      e,
      id,
      'PUT',
      `/api/settings/catalog/${collection}/flags/${flag}`,
      body,
    );
  }
  @Get(':environment/:id/integrations') integrations(
    @Req() r: PlatformRequest,
    @Param('environment') e: string,
    @Param('id') id: string,
  ) {
    return this.forward(r, e, id, 'GET', '/api/settings/integrations');
  }
  @Put(':environment/:id/integrations/:connectionId') credential(
    @Req() r: PlatformRequest,
    @Param('environment') e: string,
    @Param('id') id: string,
    @Param('connectionId') connectionId: string,
    @Body() body: unknown,
  ) {
    return this.forward(
      r,
      e,
      id,
      'PUT',
      `/api/settings/integrations/${connectionId}`,
      body,
    );
  }
  @Patch(':environment/:id/integrations/:connectionId') state(
    @Req() r: PlatformRequest,
    @Param('environment') e: string,
    @Param('id') id: string,
    @Param('connectionId') connectionId: string,
    @Body() body: unknown,
  ) {
    return this.forward(
      r,
      e,
      id,
      'PATCH',
      `/api/settings/integrations/${connectionId}`,
      body,
    );
  }
  @Post(':environment/:id/integrations/:provider/connect') connect(
    @Req() r: PlatformRequest,
    @Param('environment') e: string,
    @Param('id') id: string,
    @Param('provider') provider: string,
  ) {
    return this.forward(
      r,
      e,
      id,
      'GET',
      provider === 'bexio'
        ? '/bexio/oauth/signin'
        : provider === 'dropbox'
          ? '/dropbox/signin'
          : '/invalid',
    );
  }
}
