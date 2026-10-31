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
import { z } from 'zod';
import { createPublicKey } from 'node:crypto';

const clubRealmSchema = z
  .array(
    z.strictObject({
      issuer: z.string().url(),
      authorizedParties: z.array(z.string().url()).min(1).max(32),
      jwtKey: z.string().min(64).max(16384),
    }),
  )
  .max(100);
export function trustedClubRealms(input: unknown, platformIssuer: string) {
  const realms = clubRealmSchema.parse(input ?? []),
    seen = new Set([platformIssuer]);
  for (const realm of realms) {
    const issuer = new URL(realm.issuer),
      key = createPublicKey(realm.jwtKey);
    if (
      seen.has(realm.issuer) ||
      issuer.origin !== realm.issuer ||
      issuer.protocol !== 'https:' ||
      issuer.username ||
      issuer.password ||
      key.asymmetricKeyType !== 'rsa' ||
      (key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048
    )
      throw Error('Invalid club Clerk realm');
    seen.add(realm.issuer);
    for (const origin of realm.authorizedParties) {
      const url = new URL(origin);
      if (
        url.origin !== origin ||
        url.username ||
        url.password ||
        (url.protocol !== 'https:' &&
          !(
            url.protocol === 'http:' &&
            (['localhost', '127.0.0.1', '[::1]'].includes(url.hostname) ||
              url.hostname.endsWith('.localhost'))
          ))
      )
        throw Error('Invalid club explorer origin');
    }
  }
  return realms;
}

export interface PlatformAuthOptions {
  clubRealms?: {
    issuer: string;
    authorizedParties: string[];
    jwtKey: string;
  }[];
  issuer: string;
  authorizedParties: string[];
  adminSubjects: string[];
  jwtKey?: string;
  secretKey?: string;
}
export const AUTH_OPTIONS = Symbol('PLATFORM_AUTH_OPTIONS');
export interface PlatformRequest extends Request {
  platformSubject: string;
  explorerSession: ExplorerSession;
}
export interface ExplorerSession {
  issuer: string;
  subject: string;
  token: string;
}
export async function verifyExplorerSession(
  options: PlatformAuthOptions,
  header: unknown,
): Promise<ExplorerSession> {
  if (
    typeof header !== 'string' ||
    !/^Bearer [A-Za-z0-9._-]+$/.test(header) ||
    header.length > 16384
  )
    throw new UnauthorizedException('Sign in to the tenant explorer');
  try {
    const token = header.slice(7);
    const hintedIssuer = (
      JSON.parse(
        Buffer.from(token.split('.')[1] ?? '', 'base64url').toString('utf8'),
      ) as { iss?: unknown }
    ).iss;
    const selected =
      hintedIssuer === options.issuer
        ? options
        : options.clubRealms?.find((realm) => realm.issuer === hintedIssuer);
    if (!selected) throw Error();
    const claims = await verifyToken(token, {
      jwtKey: selected.jwtKey,
      secretKey: 'secretKey' in selected ? selected.secretKey : undefined,
      authorizedParties: selected.authorizedParties,
    });
    if (
      claims.iss !== selected.issuer ||
      !claims.sub ||
      !claims.sid ||
      typeof claims.azp !== 'string' ||
      !selected.authorizedParties.includes(claims.azp)
    )
      throw Error();
    return { issuer: claims.iss, subject: claims.sub, token };
  } catch {
    throw new UnauthorizedException('Explorer session is invalid or expired');
  }
}
@Injectable()
export class ExplorerSessionGuard implements CanActivate {
  constructor(
    @Inject(AUTH_OPTIONS) private readonly options: PlatformAuthOptions,
  ) {
    this.options = {
      ...options,
      clubRealms: trustedClubRealms(options.clubRealms, options.issuer),
    };
  }
  async canActivate(context: ExecutionContext) {
    const request = context.switchToHttp().getRequest<PlatformRequest>();
    request.explorerSession = await verifyExplorerSession(
      this.options,
      request.headers.authorization,
    );
    return true;
  }
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
