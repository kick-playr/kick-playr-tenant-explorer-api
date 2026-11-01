import {
  ConflictException,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { parse } from '../contracts.js';
import {
  checklist,
  removeSchema,
  operationSchema,
  purgeSchema,
  recoveryDeadline,
  scopeKey,
  type Scope,
  type DeletionState,
  type DeletionStore,
  type PurgePort,
  type Operation,
} from './contracts.js';
const changed = () =>
  new ConflictException(
    'Tenant changed; review updated impact before confirming',
  );
export class DeletionService {
  constructor(
    private readonly store: DeletionStore,
    private readonly purger: PurgePort,
    private readonly clock = () => Date.now(),
  ) {}
  private check(
    s: Scope,
    x: DeletionState,
    revision: number,
    confirmation: string,
  ) {
    if (confirmation !== scopeKey(s))
      throw new ConflictException(
        'Tenant confirmation must match environment/tenantId',
      );
    if (x.tenant.definition.configRevision !== revision) throw changed();
  }
  private op(x: DeletionState, id: string) {
    if (!x.operation || x.operation.id !== id) throw changed();
    return x.operation;
  }
  private advance(x: DeletionState) {
    const d = x.tenant.definition,
      a = x.tenant.authority;
    if (!a) throw new ConflictException('Tenant authority unavailable');
    if (
      [d.configRevision, a.authorityRevision, a.supportRevision ?? 0].some(
        (v) => !Number.isSafeInteger(v) || v >= Number.MAX_SAFE_INTEGER - 1,
      )
    )
      throw changed();
    d.configRevision++;
    a.configRevision = d.configRevision;
    a.authorityRevision++;
    a.supportRevision = (a.supportRevision ?? 0) + 1;
    d.status = 'disabled';
    a.status = 'disabled';
  }
  private view(x: DeletionState) {
    return {
      operation: x.operation ?? null,
      expectedRevision: x.tenant.definition.configRevision,
      expectedAuthorityRevision: x.tenant.authority?.authorityRevision ?? 0,
      expectedInvitationRevision: x.invitations?.revision ?? 0,
      identity: {
        name: x.tenant.definition.public.name,
        hostname: x.tenant.definition.hostname,
        aliases: x.tenant.definition.aliases,
      },
      impact: {
        users:
          x.tenant.authority?.users.filter((u) => u.status === 'active')
            .length ?? 0,
        pendingInvitations:
          x.invitations?.invitations.filter((i) => i.state === 'pending')
            .length ?? 0,
      },
      checklist,
      purgeInProgress:
        x.operation?.phase === 'purging' &&
        Number(x.operation.leaseUntil) > this.clock(),
      recoveryAvailable:
        x.operation?.phase === 'retained' &&
        this.clock() < Date.parse(x.operation.recoverUntil),
    };
  }
  async status(s: Scope) {
    scopeKey(s);
    const current = await this.store.transact(s, async (x) => this.view(x));
    let inventory;
    try {
      inventory = await this.purger.inventory(s);
    } catch (error) {
      inventory = {
        revision: 'unavailable',
        complete: false,
        targets: [],
        reason:
          error instanceof ConflictException
            ? error.message
            : 'Registered database inventory unavailable; review the authoritative runtime configuration',
      };
    }
    return { ...current, inventory };
  }
  async remove(s: Scope, body: unknown, actor: string) {
    const b = parse(removeSchema, body);
    return this.store.transact(s, async (x) => {
      this.check(s, x, b.expectedRevision, b.confirmation);
      if ((x.invitations?.revision ?? 0) !== b.expectedInvitationRevision)
        throw changed();
      if (x.tenant.authority?.authorityRevision !== b.expectedAuthorityRevision)
        throw changed();
      if (x.tenant.definition.deletionId)
        throw new ConflictException('Tenant already marked for deletion');
      this.advance(x);
      const now = new Date(this.clock()).toISOString();
      const op: Operation = {
        ...s,
        id: randomUUID(),
        phase: 'retained',
        deletedAt: now,
        recoverUntil: recoveryDeadline(now),
        revision: 1,
        targets: [],
      };
      x.operation = op;
      x.tenant.definition.deletionId = op.id;
      const a = x.tenant.authority!;
      for (const u of a.users) {
        u.status = 'revoked';
        u.revision++;
      }
      a.services = a.services.map((v) =>
        v && typeof v === 'object'
          ? {
              ...v,
              status: 'revoked',
              revision: Number((v as any).revision ?? 0) + 1,
            }
          : v,
      );
      if (x.invitations) {
        x.invitations.revision++;
        for (const p of x.invitations.principals) p.state = 'revoked';
        for (const i of x.invitations.invitations) {
          i.state = 'revoked';
          delete i.delivery.envelope;
        }
      }
      x.event = { action: 'tenant.deletion.requested', actor };
      return this.view(x);
    });
  }
  async recover(s: Scope, body: unknown, actor: string) {
    const b = parse(operationSchema, body);
    return this.store.transact(s, async (x) => {
      this.check(s, x, b.expectedRevision, b.confirmation);
      const op = this.op(x, b.operationId);
      if (op.revision !== b.expectedOperationRevision) throw changed();
      if (
        op.phase !== 'retained' ||
        this.clock() >= Date.parse(op.recoverUntil)
      )
        throw new ConflictException(
          'Recovery period ended or permanent deletion started',
        );
      this.advance(x);
      delete x.tenant.definition.deletionId;
      op.phase = 'recovered';
      op.revision++;
      x.event = { action: 'tenant.deletion.recovered', actor };
      return this.view(x);
    });
  }
  async purge(s: Scope, body: unknown, actor: string) {
    const b = parse(purgeSchema, body);
    if (
      new Set(b.completed).size !== checklist.length ||
      checklist.some((c) => !b.completed.includes(c.id))
    )
      throw new ConflictException(
        'Complete every manual cleanup checklist item',
      );
    const inventory = await this.purger.inventory(s);
    if (inventory.revision !== b.expectedInventoryRevision) throw changed();
    if (!inventory.complete)
      throw new ConflictException(
        'Complete verified database inventory required',
      );
    if (
      b.controlOnly !==
      (inventory.controlOnly ?? inventory.targets.length === 0)
    )
      throw new ConflictException(
        'Confirm the displayed registered-database or control-only cleanup scope',
      );
    const lease = randomUUID();
    const work = await this.store.transact(s, async (x, transaction) => {
      this.check(s, x, b.expectedRevision, b.confirmation);
      const op = this.op(x, b.operationId);
      if (op.revision !== b.expectedOperationRevision) throw changed();
      if (op.phase === 'purged') return null;
      if (op.phase === 'recovered')
        throw new ConflictException(
          'Tenant must be deleted before permanent purge',
        );
      if (
        x.invitations?.invitations.some(
          (i) => Number(i.delivery.leaseUntil) > this.clock(),
        )
      )
        throw new ConflictException(
          'Waiting for active invitation delivery; reconcile ongoing work',
        );
      if (op.leaseId && Number(op.leaseUntil) > this.clock())
        throw new ConflictException(
          'Permanent deletion already in progress; reload status',
        );
      if (op.manifestRevision && op.manifestRevision !== inventory.revision)
        throw new ConflictException(
          'Database inventory changed; operator review required',
        );
      await transaction.reserveTargets(op.id, inventory.revision);
      op.manifestRevision = inventory.revision;
      op.targets = inventory.targets.map((t) => ({
        ...t,
        done: op.targets.find((p) => p.id === t.id)?.done ?? false,
      }));
      op.phase = 'purging';
      op.actor = actor;
      op.leaseId = lease;
      op.leaseUntil = this.clock() + 120000;
      op.revision++;
      delete op.error;
      x.event = { action: 'tenant.deletion.purge-started', actor };
      return structuredClone(op);
    });
    if (!work) return this.status(s);
    const owned = async (edit: (op: Operation) => void) =>
      this.store.transact(s, async (x) => {
        const op = this.op(x, work.id);
        if (op.leaseId !== lease || Number(op.leaseUntil) <= this.clock())
          throw new ConflictException(
            'Deletion lease expired; reload and retry',
          );
        edit(op);
        op.revision++;
        return this.view(x);
      });
    try {
      for (const target of work.targets) {
        await owned((op) => {
          op.leaseUntil = this.clock() + 120000;
        });
        const fresh = await this.purger.inventory(s);
        if (!fresh.complete || fresh.revision !== work.manifestRevision)
          throw changed();
        if (!target.done) await this.purger.erase(s, target.id);
        if (!(await this.purger.absent(s, target.id)))
          throw new ServiceUnavailableException(
            'Database deletion could not be verified',
          );
        await owned((op) => {
          op.targets.find((t) => t.id === target.id)!.done = true;
        });
      }
      await this.store.finish(s, work.id, lease);
      await owned((op) => {
        op.phase = 'purged';
        op.completedAt = new Date(this.clock()).toISOString();
        delete op.leaseId;
        delete op.leaseUntil;
      });
    } catch {
      await this.store.transact(s, async (x) => {
        const op = this.op(x, work.id);
        if (op.leaseId === lease) {
          op.phase = 'failed';
          op.error =
            'Cleanup incomplete. Review database inventory and ongoing work, then retry failed steps.';
          delete op.leaseId;
          delete op.leaseUntil;
          op.revision++;
          x.event = { action: 'tenant.deletion.purge-failed', actor };
        }
      });
    }
    return this.status(s);
  }
}
