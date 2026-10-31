import { createClerkClient, verifyToken } from '@clerk/backend';
import { UnauthorizedException } from '@nestjs/common';
import { z } from 'zod';
import type { Identity, IdentityPort, RealmBinding } from './types.js';
const httpsOrigin = z
  .string()
  .url()
  .refine((v) => {
    const u = new URL(v);
    return u.origin === v && u.protocol === 'https:';
  });
const bindingSchema = z.strictObject({
  environment: z.enum(['development', 'test', 'preview', 'production']),
  tenantId: z.string().regex(/^[a-z0-9][a-z0-9-]{0,63}$/),
  issuer: httpsOrigin,
  origin: z.string().url(),
  audience: z.string().min(1).max(256),
  authorizedParties: z.array(z.string().url()).min(1).max(16),
  secretKeyEnv: z.string().regex(/^[A-Z][A-Z0-9_]{1,100}$/),
});
export function invitationBindings(
  raw: string | undefined,
  env: Record<string, string | undefined>,
): RealmBinding[] {
  const rows = z
    .array(bindingSchema)
    .max(128)
    .parse(JSON.parse(raw || '[]'));
  if (
    new Set(rows.map((r) => `${r.environment}/${r.tenantId}`)).size !==
    rows.length
  )
    throw Error('Duplicate invitation binding');
  return rows.map(({ secretKeyEnv, ...r }) => {
    for (const v of [r.origin, ...r.authorizedParties]) {
      const u = new URL(v);
      if (
        u.origin !== v ||
        u.username ||
        u.password ||
        !(
          u.protocol === 'https:' ||
          (r.environment === 'development' &&
            u.protocol === 'http:' &&
            (u.hostname.endsWith('.localhost') ||
              ['localhost', '127.0.0.1'].includes(u.hostname)))
        )
      )
        throw Error('Invalid invitation origin');
    }
    if (!r.authorizedParties.includes(r.origin) || !env[secretKeyEnv])
      throw Error('Invitation identity configuration unavailable');
    return { ...r, secretKey: env[secretKeyEnv]! };
  });
}
/** Separate setup admission: no existing tenant membership required, no runtime grants issued. */
export class ClerkInvitationIdentity implements IdentityPort {
  constructor(private readonly sdk = { verifyToken, createClerkClient }) {}
  async verify(b: RealmBinding, token: string): Promise<Identity> {
    try {
      if (
        token.length > 16384 ||
        !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)
      )
        throw Error();
      const claims = await this.sdk.verifyToken(token, {
        secretKey: b.secretKey,
        audience: b.audience,
        authorizedParties: b.authorizedParties,
      });
      if (
        claims.iss !== b.issuer ||
        !claims.sub ||
        !claims.sid ||
        typeof claims.azp !== 'string' ||
        !b.authorizedParties.includes(claims.azp) ||
        typeof claims.exp !== 'number' ||
        claims.exp <= Date.now() / 1000 ||
        typeof claims.nbf !== 'number' ||
        claims.nbf > Date.now() / 1000 + 5
      )
        throw Error();
      const client = this.sdk.createClerkClient({ secretKey: b.secretKey });
      const [session, user] = await Promise.all([
        client.sessions.getSession(claims.sid),
        client.users.getUser(claims.sub),
      ]);
      if (
        session.status !== 'active' ||
        session.userId !== claims.sub ||
        session.id !== claims.sid ||
        user.id !== claims.sub ||
        user.banned !== false ||
        user.locked !== false ||
        claims.exp <= Date.now() / 1000
      )
        throw Error();
      return {
        issuer: b.issuer,
        subject: user.id,
        sessionId: session.id,
        emails: user.emailAddresses
          .filter((e) => e.verification?.status === 'verified')
          .map((e) => e.emailAddress),
      };
    } catch {
      throw new UnauthorizedException('Sign in with the intended club account');
    }
  }
  async resolve(b: RealmBinding, subject: string): Promise<Identity> {
    try {
      const user = await this.sdk
        .createClerkClient({ secretKey: b.secretKey })
        .users.getUser(subject);
      if (user.id !== subject || user.banned !== false || user.locked !== false)
        throw Error();
      return {
        issuer: b.issuer,
        subject,
        sessionId: '',
        emails: user.emailAddresses
          .filter((e) => e.verification?.status === 'verified')
          .map((e) => e.emailAddress),
      };
    } catch {
      throw new UnauthorizedException('Recipient unavailable');
    }
  }
}
