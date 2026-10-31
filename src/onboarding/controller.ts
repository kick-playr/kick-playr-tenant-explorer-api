import { RuntimeMongoService } from '../runtime-mongo.js';
import {
  Body,
  Controller,
  Get,
  Inject,
  Param,
  Post,
  Req,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import { z } from 'zod';
import type { Request } from 'express';
import { environmentSchema, identifier, parse } from '../contracts.js';
import {
  AUTH_OPTIONS,
  PlatformGuard,
  type PlatformAuthOptions,
  type PlatformRequest,
} from '../auth.js';
import { InvitationPlatformGuard } from '../invitations/controller.js';
import { OnboardingService } from './service.js';
import { TenantService } from '../tenant.service.js';
const scope = (environment: string, tenantId: string) => ({
  environment: parse(environmentSchema, environment),
  tenantId: parse(identifier, tenantId),
});
function bearer(req: Request) {
  const h = req.headers.authorization;
  if (!h?.startsWith('Bearer ') || h.length > 16400)
    throw new UnauthorizedException('Bitte anmelden');
  return h.slice(7);
}
@Controller('api/onboarding/:environment/:tenantId')
@Throttle({ default: { limit: 30, ttl: 60000 } })
export class OnboardingController {
  constructor(
    @Inject(OnboardingService) private readonly service: OnboardingService,
  ) {}
  @Get('status') status(
    @Param('environment') e: string,
    @Param('tenantId') t: string,
    @Req() req: Request,
  ) {
    return this.service.status(scope(e, t), bearer(req));
  }
  @Post('actions/:action') run(
    @Param('environment') e: string,
    @Param('tenantId') t: string,
    @Param('action') action: string,
    @Req() req: Request,
    @Body() body: unknown,
  ) {
    const a = parse(
      z.enum([
        'settings',
        'save-settings',
        'bexio',
        'bexio-configure',
        'bexio-start',
        'bexio-finish',
        'contacts',
        'contact',
      ]),
      action,
    );
    return this.service.run(scope(e, t), bearer(req), a, body);
  }
  @Post('complete') complete(
    @Param('environment') e: string,
    @Param('tenantId') t: string,
    @Req() req: Request,
    @Body() body: unknown,
  ) {
    const input = parse(
      z.strictObject({ expectedRevision: z.number().int().positive() }),
      body,
    );
    return this.service.complete(
      scope(e, t),
      bearer(req),
      input.expectedRevision,
    );
  }
  @Get('reviews') reviews(
    @Param('environment') e: string,
    @Param('tenantId') t: string,
    @Req() req: Request,
  ) {
    return this.service.reviews(scope(e, t), bearer(req));
  }
  @Post('review-contact') reviewContact(
    @Param('environment') e: string,
    @Param('tenantId') t: string,
    @Req() req: Request,
    @Body() body: unknown,
  ) {
    return this.service.reviewContact(scope(e, t), bearer(req), body);
  }
  @Post('confirm') confirm(
    @Param('environment') e: string,
    @Param('tenantId') t: string,
    @Req() req: Request,
    @Body() body: unknown,
  ) {
    return this.service.confirm(scope(e, t), bearer(req), body);
  }
}
@Controller('api/platform/tenants/:environment/:tenantId/onboarding')
export class ProvisioningController {
  constructor(
    @Inject(OnboardingService) private readonly service: OnboardingService,
    @Inject(TenantService) private readonly tenants: TenantService,
    @Inject(AUTH_OPTIONS) private readonly auth: PlatformAuthOptions,
    @Inject(RuntimeMongoService) private readonly mongo: RuntimeMongoService,
  ) {}
  @Get()
  @UseGuards(PlatformGuard)
  async get(@Param('environment') e: string, @Param('tenantId') t: string) {
    const s = scope(e, t),
      guide = await this.service.provisioning(s),
      keys = await this.tenants.keyFiles(e, t);
    const variables = keys.files.length
      ? keys.files.map((f) => f.variable).filter(Boolean)
      : Object.values(guide.proposedVariables);
    return {
      ...guide,
      keys,
      mongo: await this.mongo.status(s),
      keySetup: await this.mongo.keyStatus(s),
      environmentSnippet: [
        ...variables.map((v) => v + '=<32-Byte-Schlüssel in Base64>'),
      ].join('\n'),
    };
  }
  @Post('configure-keys')
  @UseGuards(InvitationPlatformGuard)
  configureKeys(
    @Param('environment') e: string,
    @Param('tenantId') t: string,
    @Req() req: PlatformRequest,
    @Body() body: unknown,
  ) {
    return this.mongo.configureKeys(scope(e, t), body, {
      issuer: this.auth.issuer,
      subject: req.platformSubject,
      expiresAt: req.platformExpiresAt,
    });
  }
  @Post('mongo-url')
  @UseGuards(InvitationPlatformGuard)
  saveMongo(
    @Param('environment') e: string,
    @Param('tenantId') t: string,
    @Req() req: PlatformRequest,
    @Body() body: unknown,
  ) {
    return this.mongo.save(scope(e, t), body, {
      subject: req.platformSubject,
      expiresAt: req.platformExpiresAt,
    });
  }
  @Post('save')
  @UseGuards(InvitationPlatformGuard)
  save(
    @Param('environment') e: string,
    @Param('tenantId') t: string,
    @Req() req: PlatformRequest,
    @Body() body: unknown,
  ) {
    return this.service.saveProvisioning(
      scope(e, t),
      {
        issuer: this.auth.issuer,
        subject: req.platformSubject,
        expiresAt: req.platformExpiresAt,
      },
      body,
    );
  }
  @Post('verify')
  @UseGuards(InvitationPlatformGuard)
  verify(
    @Param('environment') e: string,
    @Param('tenantId') t: string,
    @Req() req: PlatformRequest,
    @Body() body: unknown,
  ) {
    parse(z.strictObject({}), body);
    return this.service.verifyProvisioning(scope(e, t), {
      issuer: this.auth.issuer,
      subject: req.platformSubject,
      expiresAt: req.platformExpiresAt,
    });
  }
}
