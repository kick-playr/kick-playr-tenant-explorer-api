import {
  HttpException,
  BadRequestException,
  ConflictException,
  ForbiddenException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { CredentialVault } from '../vault.js';
import type {
  DeliveryPort,
  Identity,
  IdentityPort,
  Invitation,
  InvitationRepository,
  InvitationTransaction,
  Manager,
  RealmBinding,
  Recipient,
  Scope,
} from './types.js';
const denied = () =>
  new ForbiddenException('Invitation or account is unavailable');
const hash = (token: string) =>
  createHash('sha256').update(token).digest('hex');
const email = (v: string) => {
  if (
    typeof v !== 'string' ||
    v.length > 254 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)
  )
    throw new BadRequestException('Enter a valid email');
  return v.toLowerCase();
};
export class InvitationService {
  constructor(
    private readonly repository: InvitationRepository,
    private readonly bindings: RealmBinding[],
    private readonly identity: IdentityPort,
    private readonly vault: CredentialVault,
    private readonly delivery: DeliveryPort,
  ) {}
  private binding(s: Scope) {
    const found = this.bindings.filter(
      (b) => b.environment === s.environment && b.tenantId === s.tenantId,
    );
    if (found.length !== 1)
      throw new ServiceUnavailableException(
        'Invitation configuration unavailable',
      );
    return found[0]!;
  }
  private async actor(s: Scope, m: Manager): Promise<Identity | undefined> {
    return m.kind === 'club'
      ? this.identity.verify(this.binding(s), m.token)
      : undefined;
  }
  private current(tx: InvitationTransaction, b: RealmBinding) {
    if (
      !['active', 'provisioning'].includes(tx.tenant.definition.status) ||
      tx.tenant.authority?.identityRealm !== b.issuer ||
      (tx.tenant.definition.status === 'active' &&
        tx.tenant.authority?.status !== 'active')
    )
      throw denied();
  }
  private manage(tx: InvitationTransaction, m: Manager, a?: Identity) {
    if (m.kind === 'platform') return;
    const owner = tx.state.owner;
    if (
      !a ||
      tx.tenant.definition.status !== 'active' ||
      !tx.state.principals.some(
        (p) =>
          p.issuer === a.issuer &&
          p.subject === a.subject &&
          p.state === 'operational' &&
          (p.role === 'main-manager' ||
            (p.role === 'owner' &&
              owner?.issuer === a.issuer &&
              owner.subject === a.subject)),
      ) ||
      !tx.tenant.authority?.users.some(
        (u) =>
          u.issuer === a.issuer &&
          u.subject === a.subject &&
          u.status === 'active',
      )
    )
      throw denied();
  }
  private rate(tx: InvitationTransaction, m: Manager, a?: Identity) {
    const key =
        m.kind === 'platform'
          ? `${m.issuer}|${m.subject}`
          : `${a!.issuer}|${a!.subject}`,
      now = Date.now();
    tx.state.rates = (tx.state.rates ?? [])
      .map((r) => ({ ...r, times: r.times.filter((t) => t > now - 60000) }))
      .filter((r) => r.times.length);
    let row = tx.state.rates.find((r) => r.actor === key);
    if (
      (row?.times.length ?? 0) >= 10 ||
      tx.state.rates.reduce((n, r) => n + r.times.length, 0) >= 60
    )
      throw new HttpException(
        'Invitation rate limit reached; retry later',
        429,
      );
    if (!row) {
      row = { actor: key, times: [] };
      tx.state.rates.push(row);
    }
    row.times.push(now);
    tx.state.lastEvent = {
      action: 'invitation.rate.reserved',
      actor: key,
      resource: 'rate-limit',
    };
  }
  private view(i: Invitation) {
    return {
      id: i.id,
      recipient: i.recipient,
      state:
        i.state === 'pending' && i.expiresAt <= Date.now()
          ? 'expired'
          : i.state,
      expiresAt: new Date(i.expiresAt).toISOString(),
      delivery: { status: i.delivery.status, attempts: i.delivery.attempts },
      bootstrap: i.bootstrap,
    };
  }
  private rotate(s: Scope, i: Invitation, b: RealmBinding) {
    const token = randomBytes(32).toString('base64url');
    i.tokenHash = hash(token);
    i.expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000;
    i.delivery = {
      status: 'queued',
      attempts: 0,
      envelope: this.vault.seal(
        this.custody(s, i),
        `${b.origin}/invitations#${token}`,
      ),
    };
  }
  private custody(s: Scope, i: Invitation) {
    return JSON.stringify([
      'invitation',
      s.environment,
      s.tenantId,
      i.id,
      i.version,
    ]);
  }
  async create(s: Scope, m: Manager, recipient: Recipient) {
    const b = this.binding(s),
      a = await this.actor(s, m);
    if (this.delivery.ready === false)
      throw new ServiceUnavailableException('Invitation email unavailable');
    await this.repository.transact(s, async (tx) => {
      this.current(tx, b);
      this.manage(tx, m, a);
    });
    let target = recipient.kind === 'email' ? email(recipient.email) : '';
    if (recipient.kind === 'subject') {
      if (!/^user_[A-Za-z0-9_-]{1,120}$/.test(recipient.subject))
        throw new BadRequestException('Enter an exact Clerk user ID');
      const resolved = await this.identity.resolve(b, recipient.subject);
      if (
        resolved.issuer !== b.issuer ||
        resolved.subject !== recipient.subject ||
        !resolved.emails.length
      )
        throw denied();
      target = email(resolved.emails[0]!);
    }
    const normalized: Recipient =
      recipient.kind === 'email'
        ? { kind: 'email', email: target }
        : { ...recipient };
    return this.repository.transact(s, async (tx) => {
      this.current(tx, b);
      this.manage(tx, m, a);
      this.rate(tx, m, a);
      const bootstrap = !tx.state.owner;
      if (bootstrap && m.kind !== 'platform') throw denied();
      if (
        tx.state.principals.some(
          (p) =>
            p.state !== 'revoked' &&
            recipient.kind === 'subject' &&
            p.subject === recipient.subject &&
            p.issuer === b.issuer,
        )
      )
        throw new ConflictException('Already a manager');
      if (
        tx.state.invitations.some(
          (i) =>
            i.email === target &&
            i.state === 'accepted' &&
            tx.state.principals.some(
              (p) => p.id === i.accepted?.membershipId && p.state !== 'revoked',
            ),
        )
      )
        throw new ConflictException('Already a manager');
      const duplicate = tx.state.invitations.find(
        (i) =>
          i.state === 'pending' &&
          i.expiresAt > Date.now() &&
          JSON.stringify(i.recipient) === JSON.stringify(normalized),
      );
      if (duplicate) return this.view(duplicate);
      if (
        bootstrap &&
        tx.state.invitations.some(
          (i) =>
            i.id === tx.state.bootstrapInvitationId &&
            i.state === 'pending' &&
            i.expiresAt > Date.now(),
        )
      )
        throw new ConflictException('An owner invitation is already pending');
      if (!bootstrap && tx.tenant.definition.status !== 'active')
        throw denied();
      // Bounded aggregate: archive historical records through a separate reviewed retention process.
      if (tx.state.invitations.length >= 128)
        throw new ConflictException('Invitation limit reached');
      const i: Invitation = {
        id: randomUUID(),
        tokenHash: '',
        version: 1,
        expectedIssuer: b.issuer,
        recipient: normalized,
        email: target,
        inviter:
          m.kind === 'platform'
            ? `${m.issuer}|${m.subject}`
            : `${a!.issuer}|${a!.subject}`,
        expiresAt: 0,
        state: 'pending',
        bootstrap,
        delivery: { status: 'queued', attempts: 0 },
      };
      this.rotate(s, i, b);
      tx.state.invitations.push(i);
      tx.state.lastEvent = {
        action: 'invitation.created',
        actor: i.inviter,
        resource: i.id,
      };
      if (bootstrap) tx.state.bootstrapInvitationId = i.id;
      return this.view(i);
    });
  }
  async list(s: Scope, m: Manager) {
    const b = this.binding(s),
      a = await this.actor(s, m);
    return this.repository.transact(s, async (tx) => {
      this.current(tx, b);
      this.manage(tx, m, a);
      return tx.state.invitations.map((i) => ({
        ...this.view(i),
        membershipState: tx.state.principals.find(
          (p) => p.id === i.accepted?.membershipId,
        )?.state,
      }));
    });
  }
  async resend(s: Scope, m: Manager, id: string) {
    const b = this.binding(s),
      a = await this.actor(s, m);
    return this.repository.transact(s, async (tx) => {
      this.current(tx, b);
      this.manage(tx, m, a);
      this.rate(tx, m, a);
      const i = tx.state.invitations.find((i) => i.id === id);
      if (
        !i ||
        i.state !== 'pending' ||
        (i.bootstrap && tx.state.bootstrapInvitationId !== id)
      )
        throw denied();
      if (
        i.delivery.status === 'sending' &&
        Number(i.delivery.leaseUntil) > Date.now()
      )
        throw new ConflictException('Delivery in progress');
      i.version++;
      this.rotate(s, i, b);
      tx.state.lastEvent = {
        action: 'invitation.resent',
        actor:
          m.kind === 'platform'
            ? `${m.issuer}|${m.subject}`
            : `${a!.issuer}|${a!.subject}`,
        resource: i.id,
      };
      return this.view(i);
    });
  }
  async revoke(s: Scope, m: Manager, id: string) {
    const b = this.binding(s),
      a = await this.actor(s, m);
    return this.repository.transact(s, async (tx) => {
      this.current(tx, b);
      this.manage(tx, m, a);
      this.rate(tx, m, a);
      const i = tx.state.invitations.find((i) => i.id === id);
      if (!i || i.state === 'accepted') throw denied();
      i.state = 'revoked';
      tx.state.lastEvent = {
        action: 'invitation.revoked',
        actor:
          m.kind === 'platform'
            ? `${m.issuer}|${m.subject}`
            : `${a!.issuer}|${a!.subject}`,
        resource: i.id,
      };
      delete i.delivery.envelope;
      return this.view(i);
    });
  }
  async revokeAccess(s: Scope, m: Manager, id: string) {
    const b = this.binding(s),
      a = await this.actor(s, m);
    return this.repository.transact(s, async (tx) => {
      this.current(tx, b);
      this.manage(tx, m, a);
      this.rate(tx, m, a);
      const i = tx.state.invitations.find(
        (i) => i.id === id && i.state === 'accepted',
      );
      const p = tx.state.principals.find(
        (p) => p.id === i?.accepted?.membershipId,
      );
      if (!i || !p || (p.role === 'owner' && m.kind !== 'platform'))
        throw denied();
      if (
        tx.tenant.authority?.users.some(
          (u) =>
            u.issuer === p.issuer &&
            u.subject === p.subject &&
            u.status !== 'revoked',
        )
      ) {
        if (!tx.revokeRuntime)
          throw new ServiceUnavailableException(
            'Runtime revocation unavailable',
          );
        await tx.revokeRuntime(p.issuer, p.subject);
      }
      p.state = 'revoked';
      tx.state.lastEvent = {
        action: 'manager.access.revoked',
        actor:
          m.kind === 'platform'
            ? `${m.issuer}|${m.subject}`
            : `${a!.issuer}|${a!.subject}`,
        resource: p.id,
      };
      return { membershipId: p.id, state: p.state };
    });
  }
  async preview(s: Scope, token: string) {
    const b = this.binding(s);
    return this.repository.transact(s, async (tx) => {
      this.current(tx, b);
      this.pending(tx, token);
      return { club: tx.tenant.definition.public.name, role: 'Vereinsmanager' };
    });
  }
  private pending(tx: InvitationTransaction, token: string) {
    if (!/^[A-Za-z0-9_-]{43}$/.test(token)) throw denied();
    const i = tx.state.invitations.find((i) => i.tokenHash === hash(token));
    if (!i || i.state === 'revoked' || i.expiresAt <= Date.now())
      throw denied();
    return i;
  }
  async accept(s: Scope, token: string, bearer: string) {
    const b = this.binding(s),
      a = await this.identity.verify(b, bearer);
    return this.repository.transact(s, async (tx) => {
      this.current(tx, b);
      const i = this.pending(tx, token);
      if (
        !a.emails.length ||
        a.issuer !== b.issuer ||
        i.expectedIssuer !== a.issuer ||
        (i.recipient.kind === 'email'
          ? !a.emails.some((e) => email(e) === i.email)
          : a.subject !== i.recipient.subject)
      )
        throw denied();
      if (i.state === 'accepted') {
        if (i.accepted?.issuer !== a.issuer || i.accepted.subject !== a.subject)
          throw denied();
        const principal = tx.state.principals.find(
          (p) => p.id === i.accepted!.membershipId,
        );
        if (!principal || principal.state === 'revoked') throw denied();
        return this.result(s, principal);
      }
      if (
        i.bootstrap &&
        (tx.state.owner || tx.state.bootstrapInvitationId !== i.id)
      )
        throw denied();
      let p = tx.state.principals.find(
        (p) => p.issuer === a.issuer && p.subject === a.subject,
      );
      if (p?.state === 'revoked') throw denied();
      p ??= {
        id: randomUUID(),
        issuer: a.issuer,
        subject: a.subject,
        state: 'setup-only',
        role: i.bootstrap ? 'owner' : 'manager',
      };
      if (!tx.state.principals.includes(p)) tx.state.principals.push(p);
      if (i.bootstrap)
        tx.state.owner = { issuer: a.issuer, subject: a.subject };
      i.state = 'accepted';
      tx.state.lastEvent = {
        action: 'invitation.accepted',
        actor: `${a.issuer}|${a.subject}`,
        resource: i.id,
      };
      i.accepted = {
        issuer: a.issuer,
        subject: a.subject,
        membershipId: p.id,
        at: new Date().toISOString(),
      };
      delete i.delivery.envelope;
      return this.result(s, p);
    });
  }
  private result(s: Scope, p: { id: string; state: string }) {
    return {
      membershipId: p.id,
      ...s,
      state: p.state,
      nextDestination: '/onboarding',
    };
  }
  async status(s: Scope, bearer: string) {
    const b = this.binding(s),
      a = await this.identity.verify(b, bearer);
    return this.repository.transact(s, async (tx) => {
      this.current(tx, b);
      if (a.issuer !== b.issuer) throw denied();
      const p = tx.state.principals.find(
        (p) =>
          p.issuer === a.issuer &&
          p.subject === a.subject &&
          p.state !== 'revoked',
      );
      if (!p) throw denied();
      return {
        ...this.result(s, p),
        state: 'blocked',
        membershipState: p.state,
        policyVersion: null,
        onboardingRevision: tx.state.revision,
        nextStep: null,
        missingPrerequisites: ['app26-unavailable'],
        operationalAccess: false,
      };
    });
  }
  async deliver(s: Scope, m: Manager, id: string) {
    const b = this.binding(s),
      a = await this.actor(s, m),
      leaseId = randomUUID();
    const claim = await this.repository.transact(s, async (tx) => {
      this.current(tx, b);
      this.manage(tx, m, a);
      this.rate(tx, m, a);
      const i = tx.state.invitations.find((i) => i.id === id);
      if (
        !i ||
        i.state !== 'pending' ||
        i.expiresAt <= Date.now() ||
        !i.delivery.envelope ||
        i.delivery.status === 'accepted'
      )
        return null;
      if (i.delivery.attempts >= 5)
        throw new ConflictException(
          'Delivery retry limit reached; resend invitation',
        );
      if (
        i.delivery.status === 'sending' &&
        Number(i.delivery.leaseUntil) > Date.now()
      )
        throw new ConflictException('Delivery in progress');
      i.delivery.status = 'sending';
      tx.state.lastEvent = {
        action: 'invitation.delivery.claimed',
        actor:
          m.kind === 'platform'
            ? `${m.issuer}|${m.subject}`
            : `${a!.issuer}|${a!.subject}`,
        resource: i.id,
      };
      i.delivery.attempts++;
      i.delivery.leaseUntil = Date.now() + 60000;
      i.delivery.leaseId = leaseId;
      return {
        to: i.email,
        url: this.vault.open(this.custody(s, i), i.delivery.envelope),
        club: tx.tenant.definition.public.name,
        id: `${i.id}:${i.version}`,
        version: i.version,
      };
    });
    if (!claim) return;
    let status: 'accepted' | 'failed' = 'failed';
    try {
      await this.delivery.send(claim);
      status = 'accepted';
    } catch {
      /* bounded retry uses the same encrypted link; never log it */
    }
    await this.repository.transact(s, async (tx) => {
      const i = tx.state.invitations.find((i) => i.id === id);
      if (i?.version === claim.version && i.delivery.leaseId === leaseId) {
        i.delivery.status = status;
        tx.state.lastEvent = {
          action: `invitation.delivery.${status}`,
          actor: 'invitation-delivery',
          resource: i.id,
        };
        delete i.delivery.leaseId;
        delete i.delivery.leaseUntil;
      }
    });
  }
}
