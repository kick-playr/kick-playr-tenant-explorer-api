import { createHmac, randomBytes } from 'node:crypto';
import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { z } from 'zod';
import { environmentSchema, identifier, parse } from '../contracts.js';
import { runtimeTransport } from '../runtime-transport.js';
export type SetupAction =
  | 'provisioning'
  | 'key-check'
  | 'settings'
  | 'save-settings'
  | 'bexio'
  | 'bexio-configure'
  | 'bexio-start'
  | 'bexio-finish'
  | 'contacts'
  | 'contact'
  | 'verify';
export interface SetupActor {
  issuer: string;
  subject: string;
  membershipId: string;
  expiresAt?: number;
}
export interface SetupScope {
  environment: string;
  tenantId: string;
}
export interface SetupRuntimePort {
  request(
    scope: SetupScope,
    actor: SetupActor,
    action: SetupAction,
    input: Record<string, unknown>,
  ): Promise<Record<string, unknown>>;
}
const bindings = z.array(
  z.object({
    environment: environmentSchema,
    tenantId: identifier,
    origin: z.string().url(),
  }),
);
export class SetupRuntime implements SetupRuntimePort {
  private readonly bindings: z.infer<typeof bindings>;
  constructor(
    value: unknown,
    private readonly keyText?: string,
    private readonly transport: typeof fetch = runtimeTransport,
  ) {
    this.bindings = parse(bindings, value);
    const seen = new Set<string>();
    for (const b of this.bindings) {
      const u = new URL(b.origin),
        id = b.environment + '/' + b.tenantId;
      if (
        seen.has(id) ||
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
        throw Error('Invalid setup destination');
      seen.add(id);
    }
  }
  async request(
    scope: SetupScope,
    actor: SetupActor,
    action: SetupAction,
    input: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    // Key inspection is platform-only on the receiver and needs no operational
    // tenant row. Reuse a database-pinned development origin for this action only.
    const b =
      this.bindings.find(
        (b) =>
          b.environment === scope.environment && b.tenantId === scope.tenantId,
      ) ??
      (action === 'key-check' && scope.environment === 'development'
        ? this.bindings.find((b) => b.environment === 'development')
        : undefined);
    const key = Buffer.from(this.keyText ?? '', 'base64');
    if (!b || key.length !== 32 || key.toString('base64') !== this.keyText) {
      key.fill(0);
      throw new ServiceUnavailableException(
        'Vereins-Setup-Verbindung oder Signaturschlüssel fehlt',
      );
    }
    const issuedAt = Date.now();
    const expiresAt = Math.min(
      issuedAt + 30000,
      actor.expiresAt ?? issuedAt + 30000,
    );
    if (!Number.isSafeInteger(expiresAt) || expiresAt <= issuedAt) {
      key.fill(0);
      throw new ForbiddenException(
        'Einrichtungssitzung abgelaufen; erneut anmelden',
      );
    }
    const raw = JSON.stringify({
      version: 1,
      nonce: randomBytes(32).toString('base64url'),
      issuedAt,
      expiresAt,
      scope,
      actor: {
        issuer: actor.issuer,
        subject: actor.subject,
        membershipId: actor.membershipId,
      },
      action,
      input,
    });
    if (Buffer.byteLength(raw) > 65536) {
      key.fill(0);
      throw new BadRequestException('Setup-Daten überschreiten 64KB');
    }
    const signature = createHmac('sha256', key)
      .update('manager-setup-v1\nPOST\n/api/internal/manager-setup\n')
      .update(raw)
      .digest('base64url');
    key.fill(0);
    try {
      const response = await this.transport(
        b.origin + '/api/internal/manager-setup',
        {
          method: 'POST',
          body: raw,
          headers: {
            'content-type': 'application/json',
            'x-manager-setup-signature': signature,
          },
          cache: 'no-store',
          redirect: 'error',
          signal: AbortSignal.timeout(25000),
        },
      );
      if (!response.headers.get('content-type')?.includes('application/json')) {
        await response.body?.cancel();
        throw Error();
      }
      if (!response.ok) {
        await response.body?.cancel();
        if (response.status === 409)
          throw new ConflictException(
            'Einrichtung wurde geändert; bitte neu laden',
          );
        if (response.status === 403 || response.status === 401)
          throw new ForbiddenException('Einrichtungszugang nicht verfügbar');
        if (response.status === 400)
          throw new BadRequestException(
            'Einrichtungsdaten oder Bexio-Kontakt prüfen',
          );
        throw Error();
      }
      const reader = response.body?.getReader();
      if (!reader) throw Error();
      const chunks: Uint8Array[] = [];
      let size = 0;
      try {
        for (;;) {
          const p = await reader.read();
          if (p.done) break;
          size += p.value.length;
          if (size > 1048576) throw Error();
          chunks.push(p.value);
        }
      } finally {
        await reader.cancel();
      }
      const result: unknown = JSON.parse(
        Buffer.concat(chunks).toString('utf8'),
      );
      if (!result || typeof result !== 'object' || Array.isArray(result))
        throw Error();
      return result as Record<string, unknown>;
    } catch (e) {
      if (
        e instanceof ConflictException ||
        e instanceof ForbiddenException ||
        e instanceof BadRequestException
      )
        throw e;
      throw new ServiceUnavailableException(
        'Vereins-Setup nicht erreichbar. Plattform-Konfiguration prüfen.',
      );
    }
  }
}
