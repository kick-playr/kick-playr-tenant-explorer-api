import {
  ForbiddenException,
  Inject,
  Injectable,
  UnauthorizedException,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import { verifyToken } from '@clerk/backend';
import type { Request } from 'express';

export interface PlatformAuthOptions {
  issuer: string;
  authorizedParties: string[];
  adminSubjects: string[];
  jwtKey?: string;
  secretKey?: string;
}
export const AUTH_OPTIONS = Symbol('PLATFORM_AUTH_OPTIONS');
export interface PlatformRequest extends Request {
  platformSubject: string;
}
@Injectable()
export class PlatformGuard implements CanActivate {
  private readonly subjects: Set<string>;
  constructor(
    @Inject(AUTH_OPTIONS) private readonly options: PlatformAuthOptions,
  ) {
    if (
      !options.issuer.startsWith('https://') ||
      !options.authorizedParties.length ||
      !options.adminSubjects.length ||
      (!options.jwtKey && !options.secretKey)
    )
      throw new Error('Platform Clerk configuration is required');
    this.subjects = new Set(options.adminSubjects);
  }
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<PlatformRequest>();
    const header = request.headers.authorization;
    if (
      !header ||
      !/^Bearer [A-Za-z0-9._-]+$/.test(header) ||
      header.length > 16384
    )
      throw new UnauthorizedException('Sign in to the tenant explorer');
    let subject: string;
    try {
      const claims = await verifyToken(header.slice(7), {
        jwtKey: this.options.jwtKey,
        secretKey: this.options.secretKey,
        authorizedParties: this.options.authorizedParties,
      });
      if (
        claims.iss !== this.options.issuer ||
        !claims.sub ||
        !claims.sid ||
        typeof claims.azp !== 'string' ||
        !this.options.authorizedParties.includes(claims.azp)
      )
        throw new Error('Invalid platform session');
      subject = claims.sub;
    } catch {
      throw new UnauthorizedException('Platform session is invalid or expired');
    }
    if (!this.subjects.has(subject))
      throw new ForbiddenException('Platform administrator access is required');
    request.platformSubject = subject;
    return true;
  }
}
