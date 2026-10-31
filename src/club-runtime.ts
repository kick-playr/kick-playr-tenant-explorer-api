import { isCatalogMappingRoute } from './catalog-policy.js';
import {
  BadRequestException,
  HttpException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { z } from 'zod';
import type { Definition } from './contracts.js';
import { environmentSchema, identifier } from './contracts.js';
import type { ExplorerSession } from './auth.js';
import { runtimeTransport } from './runtime-transport.js';

const bindingSchema = z.strictObject({
  tenantId: identifier,
  environment: environmentSchema,
  hostname: z.string().min(1).max(253),
  origin: z.string().url(),
});
export type RuntimeBinding = z.infer<typeof bindingSchema>;
/** Fixed server-owned tenant proxy destinations. No database or plaintext-secret custody. */
export class ClubRuntime {
  private readonly bindings: RuntimeBinding[];
  constructor(
    bindings: unknown = [],
    private readonly transport: typeof fetch = runtimeTransport,
  ) {
    this.bindings = z.array(bindingSchema).max(100).parse(bindings);
    const seen = new Set<string>();
    for (const b of this.bindings) {
      const u = new URL(b.origin),
        key = b.environment + '/' + b.tenantId;
      if (
        seen.has(key) ||
        u.origin !== b.origin ||
        u.username ||
        u.password ||
        (u.protocol !== 'https:' &&
          !(
            b.environment === 'development' &&
            u.protocol === 'http:' &&
            (['localhost', '127.0.0.1', '[::1]'].includes(u.hostname) ||
              u.hostname.endsWith('.localhost'))
          ))
      )
        throw Error('Invalid club runtime configuration');
      seen.add(key);
    }
  }
  async request(
    tenant: Definition,
    session: ExplorerSession,
    method: string,
    path: string,
    body?: unknown,
  ): Promise<unknown> {
    if (!(
      (path === '/api/settings' && ['GET', 'PATCH'].includes(method)) ||
      (path === '/api/settings/branding' && method === 'GET') ||
      isCatalogMappingRoute(method, path) ||
      (path === '/api/settings/integrations' && method === 'GET') ||
      (/^\/api\/settings\/integrations\/[a-z0-9][a-z0-9-]{0,63}$/.test(path) &&
        ['PUT', 'PATCH'].includes(method)) ||
      (['/bexio/oauth/signin', '/dropbox/signin'].includes(path) &&
        method === 'GET')
    ))
      throw new BadRequestException('Invalid club settings operation');
    const binding = this.bindings.find(
      (b) =>
        b.tenantId === tenant.id &&
        b.environment === tenant.environment &&
        b.hostname === tenant.hostname,
    );
    if (!binding)
      throw new ServiceUnavailableException(
        'The club runtime connection is not configured',
      );
    const raw = body === undefined ? undefined : JSON.stringify(body);
    if (raw && Buffer.byteLength(raw) > 65536)
      throw new BadRequestException('Settings exceed 64KB');
    const scheme =
      tenant.environment === 'development' &&
      tenant.hostname.includes('.localhost:')
        ? 'http'
        : 'https';
    let response: Response;
    try {
      response = await this.transport(binding.origin + path, {
        method,
        body: raw,
        redirect: 'error',
        cache: 'no-store',
        signal: AbortSignal.timeout(15000),
        headers: {
          Authorization: 'Bearer ' + session.token,
          Host: binding.hostname,
          Origin: scheme + '://' + binding.hostname,
          'Content-Type': 'application/json',
          Accept: 'application/json',
          'x-kick-playr-role': 'ADMIN',
        },
      });
      if (!response.headers.get('content-type')?.includes('application/json')) {
        await response.body?.cancel();
        throw Error();
      }
      if (!response.ok) {
        await response.body?.cancel();
        const status = [400, 401, 403, 404, 409, 413, 429].includes(
          response.status,
        )
          ? response.status
          : 503;
        let missingAudience = false;
        if (status === 401) {
          try {
            // Identity was verified by ExplorerSessionGuard. Inspect only to
            // explain rejection; never authorize or disclose the bearer here.
            const claims = JSON.parse(
              Buffer.from(
                session.token.split('.')[1] ?? '',
                'base64url',
              ).toString('utf8'),
            ) as { aud?: unknown };
            missingAudience = claims.aud === undefined;
          } catch {
            /* Preserve the generic rejection for malformed tokens. */
          }
        }
        throw new HttpException(
          missingAudience
            ? 'Your Clerk session token is missing the club API audience. Configure the club session token claims, then sign in again.'
            : status === 409
              ? 'Club settings changed; reload before saving'
              : status === 403
                ? 'Club administrator permission is required'
                : 'Club runtime request was rejected',
          status,
        );
      }
      const reader = response.body?.getReader();
      if (!reader) throw Error();
      let length = 0;
      const chunks: Uint8Array[] = [];
      try {
        for (;;) {
          const part = await reader.read();
          if (part.done) break;
          length += part.value.byteLength;
          // Tenant encrypted settings records permit up to one MiB.
          if (length > 1024 * 1024) throw Error();
          chunks.push(part.value);
        }
      } finally {
        await reader.cancel();
      }
      return JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch (error) {
      if (error instanceof HttpException) throw error;
      throw new ServiceUnavailableException('Club runtime is unavailable');
    }
  }
}
