import {
  ForbiddenException,
  ServiceUnavailableException,
} from '@nestjs/common';
import type { Repository } from './repository.js';
import type { Aggregate, Definition } from './contracts.js';
import { environmentSchema, identifier, parse } from './contracts.js';
import type { ExplorerSession } from './auth.js';
import { randomUUID } from 'node:crypto';

export class ClubAccess {
  constructor(private readonly repository: Repository) {}
  private allowed(
    a: Aggregate | null,
    session: ExplorerSession,
  ): a is Aggregate {
    if (!a || a.definition.status !== 'active') return false;
    const d = a.definition,
      r = a.authority;
    if (
      !r ||
      r.schema !== 1 ||
      r.status !== 'active' ||
      r.tenantId !== d.id ||
      r.environment !== d.environment ||
      r.configRevision !== d.configRevision ||
      r.identityRealm !== session.issuer ||
      !r.hostnames.includes(d.hostname)
    )
      return false;
    const grants = r.users.filter(
      (g) => g.issuer === session.issuer && g.subject === session.subject,
    );
    return (
      grants.length === 1 &&
      grants[0]!.status === 'active' &&
      ['club:settings:read', 'club:settings:write'].every((p) =>
        grants[0]!.permissions.includes(p),
      )
    );
  }
  async require(
    environment: string,
    id: string,
    session: ExplorerSession,
  ): Promise<Definition> {
    parse(environmentSchema, environment);
    parse(identifier, id);
    const a = await this.repository.read(environment, id);
    if (!this.allowed(a, session))
      throw new ForbiddenException('Club administrator access is required');
    return a.definition;
  }
  async list(session: ExplorerSession) {
    if (!this.repository.clubDefinitions)
      throw new ServiceUnavailableException('Club access is unavailable');
    const candidates = await this.repository.clubDefinitions(
        session.issuer,
        session.subject,
      ),
      items = [];
    for (const d of candidates) {
      const a = await this.repository.read(d.environment, d.id);
      if (this.allowed(a, session))
        items.push({
          id: a.definition.id,
          environment: a.definition.environment,
          public: a.definition.public,
        });
    }
    if (!items.length)
      throw new ForbiddenException('No active club administrator grant');
    return { items };
  }
  async audit(tenant: Definition, session: ExplorerSession, action: string) {
    await this.repository.transaction(async (tx) => {
      const a = await tx.read(tenant.environment, tenant.id);
      if (!this.allowed(a, session))
        throw new ForbiddenException('Club administrator access is required');
      await tx.appendAudit({
        id: randomUUID(),
        environment: tenant.environment,
        tenantId: tenant.id,
        action,
        actor: session.issuer + '|' + session.subject,
        revision: a.definition.configRevision,
        at: new Date().toISOString(),
      });
    });
  }
}
