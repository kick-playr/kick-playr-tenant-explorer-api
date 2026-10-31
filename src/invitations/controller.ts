import {
  Body,
  Controller,
  Get,
  Inject,
  Param,
  Post,
  Req,
  UseGuards,
  UnauthorizedException,
  Injectable,
  type ExecutionContext,
} from '@nestjs/common';
import { createClerkClient, verifyToken } from '@clerk/backend';
import { Throttle } from '@nestjs/throttler';
import type { Request } from 'express';
import { z } from 'zod';
import {
  AUTH_OPTIONS,
  PlatformGuard,
  type PlatformAuthOptions,
  type PlatformRequest,
} from '../auth.js';
import { parse } from '../contracts.js';
import { InvitationService } from './service.js';
import type { Manager, Scope } from './types.js';
const scopeSchema = z.strictObject({
  environment: z.enum(['development', 'test', 'preview', 'production']),
  tenantId: z.string().regex(/^[a-z0-9][a-z0-9-]{0,63}$/),
});
const recipientSchema = z.discriminatedUnion('kind', [
  z.strictObject({
    kind: z.literal('email'),
    email: z.string().email().max(254),
  }),
  z.strictObject({
    kind: z.literal('subject'),
    subject: z.string().regex(/^user_[A-Za-z0-9_-]{1,120}$/),
  }),
]);
const tokenSchema = z.strictObject({
  token: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
});
function bearer(req: Request) {
  const h = req.headers.authorization;
  if (!h?.startsWith('Bearer ') || h.length > 16400)
    throw new UnauthorizedException('Sign in');
  return h.slice(7);
}
function scope(environment: string, tenantId: string): Scope {
  return parse(scopeSchema, { environment, tenantId });
}
export function assertLivePlatformSession(
  claims: { iss?: unknown; sub?: unknown; sid?: unknown; exp?: unknown },
  session: { id: string; userId: string; status: string },
  user: { id: string; banned: boolean; locked: boolean },
  issuer: string,
  subject: string,
) {
  if (
    claims.iss !== issuer ||
    claims.sub !== subject ||
    typeof claims.exp !== 'number' ||
    claims.exp <= Date.now() / 1000 ||
    session.status !== 'active' ||
    session.userId !== subject ||
    session.id !== claims.sid ||
    user.id !== subject ||
    user.banned !== false ||
    user.locked !== false
  )
    throw new UnauthorizedException('Platform session unavailable');
}
@Injectable()
export class InvitationPlatformGuard extends PlatformGuard {
  constructor(
    @Inject(AUTH_OPTIONS) private readonly config: PlatformAuthOptions,
  ) {
    super(config);
  }
  override async canActivate(context: ExecutionContext) {
    await super.canActivate(context);
    const req = context.switchToHttp().getRequest<PlatformRequest>();
    try {
      if (!this.config.secretKey) throw Error();
      const claims = await verifyToken(bearer(req), {
        secretKey: this.config.secretKey,
        authorizedParties: this.config.authorizedParties,
      });
      const client = createClerkClient({ secretKey: this.config.secretKey });
      const [session, user] = await Promise.all([
        client.sessions.getSession(claims.sid!),
        client.users.getUser(claims.sub),
      ]);
      assertLivePlatformSession(
        claims,
        session,
        user,
        this.config.issuer,
        req.platformSubject,
      );
      return true;
    } catch {
      throw new UnauthorizedException('Platform session unavailable');
    }
  }
}
@Controller('api/platform/tenants/:environment/:tenantId/invitations')
@UseGuards(InvitationPlatformGuard)
@Throttle({ default: { limit: 10, ttl: 60000 } })
export class PlatformInvitationsController {
  constructor(
    @Inject(InvitationService) private readonly invitations: InvitationService,
    @Inject(AUTH_OPTIONS) private readonly auth: PlatformAuthOptions,
  ) {}
  private manager(req: PlatformRequest): Manager {
    return {
      kind: 'platform',
      issuer: this.auth.issuer,
      subject: req.platformSubject,
    };
  }
  @Get() list(
    @Param('environment') e: string,
    @Param('tenantId') t: string,
    @Req() r: PlatformRequest,
  ) {
    return this.invitations.list(scope(e, t), this.manager(r));
  }
  @Post() create(
    @Param('environment') e: string,
    @Param('tenantId') t: string,
    @Req() r: PlatformRequest,
    @Body() body: unknown,
  ) {
    return this.invitations.create(
      scope(e, t),
      this.manager(r),
      parse(recipientSchema, body),
    );
  }
  @Post(':id/:action') async action(
    @Param('environment') e: string,
    @Param('tenantId') t: string,
    @Param('id') id: string,
    @Param('action') action: string,
    @Req() r: PlatformRequest,
    @Body() body: unknown,
  ) {
    parse(z.strictObject({}), body);
    const a = parse(
        z.enum(['resend', 'revoke', 'deliver', 'revoke-access']),
        action,
      ),
      key = scope(e, t),
      m = this.manager(r);
    if (a === 'deliver') {
      await this.invitations.deliver(key, m, id);
      return { status: 'processed' };
    }
    if (a === 'revoke-access') return this.invitations.revokeAccess(key, m, id);
    return a === 'resend'
      ? this.invitations.resend(key, m, id)
      : this.invitations.revoke(key, m, id);
  }
}
@Controller('api/club/tenants/:environment/:tenantId/invitations')
@Throttle({ default: { limit: 10, ttl: 60000 } })
export class ClubInvitationsController {
  constructor(
    @Inject(InvitationService) private readonly invitations: InvitationService,
  ) {}
  @Get() list(
    @Param('environment') e: string,
    @Param('tenantId') t: string,
    @Req() r: Request,
  ) {
    return this.invitations.list(scope(e, t), {
      kind: 'club',
      token: bearer(r),
    });
  }
  @Post() create(
    @Param('environment') e: string,
    @Param('tenantId') t: string,
    @Req() r: Request,
    @Body() body: unknown,
  ) {
    return this.invitations.create(
      scope(e, t),
      { kind: 'club', token: bearer(r) },
      parse(recipientSchema, body),
    );
  }
  @Post(':id/:action') async action(
    @Param('environment') e: string,
    @Param('tenantId') t: string,
    @Param('id') id: string,
    @Param('action') action: string,
    @Req() r: Request,
    @Body() body: unknown,
  ) {
    parse(z.strictObject({}), body);
    const a = parse(
        z.enum(['resend', 'revoke', 'deliver', 'revoke-access']),
        action,
      ),
      key = scope(e, t),
      m: Manager = { kind: 'club', token: bearer(r) };
    if (a === 'deliver') {
      await this.invitations.deliver(key, m, id);
      return { status: 'processed' };
    }
    if (a === 'revoke-access') return this.invitations.revokeAccess(key, m, id);
    return a === 'resend'
      ? this.invitations.resend(key, m, id)
      : this.invitations.revoke(key, m, id);
  }
}
@Controller('api/invitations/:environment/:tenantId')
@Throttle({ default: { limit: 10, ttl: 60000 } })
export class AcceptanceController {
  constructor(
    @Inject(InvitationService) private readonly invitations: InvitationService,
  ) {}
  @Post('preview') preview(
    @Param('environment') e: string,
    @Param('tenantId') t: string,
    @Body() body: unknown,
  ) {
    return this.invitations.preview(
      scope(e, t),
      parse(tokenSchema, body).token,
    );
  }
  @Post('accept') accept(
    @Param('environment') e: string,
    @Param('tenantId') t: string,
    @Body() body: unknown,
    @Req() req: Request,
  ) {
    return this.invitations.accept(
      scope(e, t),
      parse(tokenSchema, body).token,
      bearer(req),
    );
  }
  @Get('status') status(
    @Param('environment') e: string,
    @Param('tenantId') t: string,
    @Req() req: Request,
  ) {
    return this.invitations.status(scope(e, t), bearer(req));
  }
}
