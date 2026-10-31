import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { z } from 'zod';
import { parse } from '../contracts.js';
import type {
  DeliveryPort,
  Identity,
  IdentityPort,
  InvitationRepository,
  InvitationTransaction,
  Principal,
  RealmBinding,
  Scope,
} from '../invitations/types.js';
import { ONBOARDING_POLICY, provisioningGuide } from './policy.js';
import type { SetupAction, SetupRuntimePort } from './runtime.js';
import type { SetupProgress } from './types.js';
const denied = () =>
  new ForbiddenException('Einrichtung oder Konto nicht verfügbar');
const revision = z
  .number()
  .int()
  .nonnegative()
  .max(Number.MAX_SAFE_INTEGER - 2);
const contactId = z.number().int().positive().max(Number.MAX_SAFE_INTEGER);
export class OnboardingService {
  constructor(
    private readonly repository: InvitationRepository,
    private readonly bindings: RealmBinding[],
    private readonly identity: IdentityPort,
    private readonly runtime: SetupRuntimePort,
    private readonly delivery?: DeliveryPort,
  ) {}
  private async actor(s: Scope, bearer: string) {
    const found = this.bindings.filter(
      (b) => b.tenantId === s.tenantId && b.environment === s.environment,
    );
    if (found.length !== 1) throw denied();
    const a = await this.identity.verify(found[0]!, bearer);
    if (a.issuer !== found[0]!.issuer || !a.emails.length) throw denied();
    return a;
  }
  private principal(tx: InvitationTransaction, a: Identity) {
    if(a.expiresAt!==undefined && a.expiresAt<=Date.now())throw denied();
    const { definition: d, authority: r } = tx.tenant;
    if (
      !['active', 'provisioning'].includes(d.status) ||
      !r ||
      r.identityRealm !== a.issuer ||
      (d.status === 'active' && r.status !== 'active')
    )
      throw denied();
    const matches = tx.state.principals.filter(
      (p) =>
        p.issuer === a.issuer &&
        p.subject === a.subject &&
        p.state !== 'revoked',
    );
    if (matches.length !== 1) throw denied();
    const p = matches[0]!;
    if(!["owner","main-manager","manager"].includes(p.role))throw denied();
    if (
      p.role === 'owner' &&
      (tx.state.owner?.issuer !== p.issuer ||
        tx.state.owner?.subject !== p.subject)
    )
      throw denied();
    if (
      p.state === 'operational' &&
      !r.users.some(
        (g) =>
          g.issuer === p.issuer &&
          g.subject === p.subject &&
          g.status === 'active',
      )
    )
      throw denied();
    return p;
  }
  private state(tx: InvitationTransaction) {
    if (
      tx.state.onboarding &&
      tx.state.onboarding.policyVersion !== ONBOARDING_POLICY
    )
      throw new ConflictException('Einrichtungsrichtlinie geändert');
    return (tx.state.onboarding ??= {
      policyVersion: ONBOARDING_POLICY,
      progress: {},
    });
  }
  private progress(tx: InvitationTransaction, p: Principal): SetupProgress {
    return (
      tx.state.onboarding?.progress[p.id] ?? {
        step: p.role === 'owner' ? 'settings' : 'contact',
      }
    );
  }
  private checkRevision(tx: InvitationTransaction, expected: unknown) {
    if (tx.state.revision !== parse(revision, expected))
      throw new ConflictException(
        'Einrichtung wurde geändert; bitte neu laden',
      );
  }
  private eligible(tx: InvitationTransaction, p: Principal) {
    if (p.state === 'operational')
      throw new ConflictException('Einrichtung bereits abgeschlossen');
    if (p.role !== 'owner' && !tx.state.onboarding?.ownerCompletedAt)
      throw new ConflictException(
        'Der erste Manager muss die Einrichtung zuerst abschliessen',
      );
  }
  private view(tx: InvitationTransaction, p: Principal, changed = false) {
    const progress = this.progress(tx, p),
      operational = p.state === 'operational';
    const missing = operational
      ? []
      : p.role !== 'owner' && !tx.state.onboarding?.ownerCompletedAt
        ? ['first-manager-onboarding']
        : progress.contactId && !progress.confirmedBy
          ? ['contact-confirmation']
          : [];
    return {
      membershipId: p.id,
      role: p.role,
      state: operational
        ? 'completed'
        : missing.length
          ? 'blocked'
          : 'in-progress',
      membershipState: p.state,
      operationalAccess: operational,
      policyVersion: ONBOARDING_POLICY,
      onboardingRevision: tx.state.revision + (changed ? 1 : 0),
      nextStep: operational
        ? null
        : missing.includes('first-manager-onboarding')
          ? null
          : progress.step,
      missingPrerequisites: missing,
      nextDestination: operational ? '/' : '/onboarding',
      progress: { ...progress },
      club: tx.tenant.definition.public.name,
    };
  }
  async status(s: Scope, bearer: string) {
    const a = await this.actor(s, bearer);
    return this.repository.transact(s, async (tx) =>
      this.view(tx, this.principal(tx, a)),
    );
  }
  async provisioning(s: Scope) {
    return this.repository.transact(s, async (tx) => {
      const binding = this.bindings.find(
        (b) => b.tenantId === s.tenantId && b.environment === s.environment,
      );
      return {
        ...provisioningGuide(s.environment, s.tenantId),
        configuredReferences: (
          tx.tenant.definition as unknown as { secretReferences?: unknown }
        ).secretReferences,
        onboardingRevision: tx.state.revision,
        operatorSteps: tx.state.onboarding?.operatorSteps ?? [],
        verification:
          tx.state.onboarding?.provisioning?.configRevision ===
          tx.tenant.definition.configRevision
            ? tx.state.onboarding.provisioning
            : null,
        emailConfigured: this.delivery?.ready === true,
        clerk: binding
          ? {
              issuer: binding.issuer,
              origin: binding.origin,
              setupAudience: binding.audience,
              secretVariable: binding.secretKeyEnv,
              claims:
                s.environment === 'development'
                  ? {
                      aud: [
                        ...new Set([
                          binding.audience,
                          `kick-playr:development:${s.tenantId}`,
                        ]),
                      ],
                    }
                  : null,
            }
          : null,
      };
    });
  }
  async saveProvisioning(
    s: Scope,
    actor: { issuer: string; subject: string; expiresAt?: number },
    body: unknown,
  ) {
    const input = parse(
      z.strictObject({
        expectedRevision: revision,
        steps: z
          .array(
            z.enum(['clerk', 'claims', 'mongodb', 'keys', 'custody', 'email']),
          )
          .max(6),
      }),
      body,
    );
    return this.repository.transact(s, async (tx) => {
      this.checkRevision(tx, input.expectedRevision);
      this.state(tx).operatorSteps = [...new Set(input.steps)];
      tx.state.lastEvent = {
        action: 'onboarding.provisioning-saved',
        actor: actor.issuer + '|' + actor.subject,
        resource: s.tenantId,
      };
      return { onboardingRevision: tx.state.revision + 1 };
    });
  }
  async verifyProvisioning(
    s: Scope,
    actor: { issuer: string; subject: string; expiresAt?: number },
  ) {
    if (this.delivery?.ready !== true || !this.delivery.verify)
      throw new ServiceUnavailableException(
        'Plattform-Mailversand zuerst konfigurieren',
      );
    const revision = await this.repository.transact(
      s,
      async (tx) => ({config:tx.tenant.definition.configRevision,setup:tx.state.revision}),
    );
    const result = await this.runtime.request(
      s,
      { ...actor, membershipId: 'platform' },
      'provisioning',
      {},
    );
    const checks = result.checks as Record<string, string> | undefined;
    if (
      !checks ||
      !['mongodb', 'keys', 'runtime'].every((k) => checks[k] === 'verified')
    )
      throw new ServiceUnavailableException(
        'Technische Voraussetzungen nicht bestätigt',
      );
    const emailReady=await this.delivery.verify();
    if(emailReady!==true || (actor.expiresAt!==undefined && actor.expiresAt<=Date.now()))throw new ServiceUnavailableException('Plattform-Mailprüfung oder Sitzung nicht bestätigt');
    checks.email = 'verified';
    return this.repository.transact(s, async (tx) => {
      if (tx.tenant.definition.configRevision !== revision.config || tx.state.revision !== revision.setup)
        throw new ConflictException('Vereinskonfiguration wurde geändert');
      this.state(tx).provisioning = {
        configRevision: revision.config,
        verifiedAt: new Date().toISOString(),
        checks,
      };
      tx.state.lastEvent = {
        action: 'onboarding.provisioning-verified',
        actor: actor.issuer + '|' + actor.subject,
        resource: s.tenantId,
      };
      return { checks, onboardingRevision: tx.state.revision + 1 };
    });
  }
  async assertProvisioned(s: Scope) {
    return this.repository.transact(s, async (tx) => {
      if (
        tx.tenant.definition.status === 'active' &&
        tx.state.onboarding?.ownerCompletedAt
      )
        return;
      const check = tx.state.onboarding?.provisioning,
        at = Date.parse(check?.verifiedAt ?? '');
      if (
        !check ||
        check.configRevision !== tx.tenant.definition.configRevision ||
        !Number.isFinite(at) ||
        at < Date.now() - 1800000 ||
        at > Date.now() + 5000 ||
        !['mongodb', 'keys', 'runtime', 'email'].every(
          (k) => check.checks[k] === 'verified',
        )
      )
        throw new ConflictException(
          'Plattform-Vorbereitung zuerst prüfen und bestätigen',
        );
    });
  }
  async reviews(s: Scope, bearer: string) {
    const a = await this.actor(s, bearer);
    return this.repository.transact(s, async (tx) => {
      const p = this.principal(tx, a);
      if (
        p.state !== 'operational' ||
        !['owner', 'main-manager'].includes(p.role)
      )
        throw denied();
      return {
        onboardingRevision: tx.state.revision,
        items: tx.state.principals
          .filter((p) => p.state === 'setup-only' && p.role !== 'owner')
          .map((p) => ({
            membershipId: p.id,
            email:
              tx.state.invitations.find(
                (i) => i.accepted?.membershipId === p.id,
              )?.email ?? '',
            contactId: this.progress(tx, p).contactId,
            confirmed: Boolean(this.progress(tx, p).confirmedBy),
          })),
      };
    });
  }
  async reviewContact(s: Scope, bearer: string, body: unknown) {
    const input = parse(
        z.strictObject({ membershipId: z.string().min(1).max(128) }),
        body,
      ),
      a = await this.actor(s, bearer);
    const candidate = await this.repository.transact(s, async (tx) => {
      const p = this.principal(tx, a);
      if (
        p.state !== 'operational' ||
        !['owner', 'main-manager'].includes(p.role)
      )
        throw denied();
      const target = tx.state.principals.find(
        (p) =>
          p.id === input.membershipId &&
          p.state === 'setup-only' &&
          p.role !== 'owner',
      );
      if (!target) throw denied();
      const progress = this.progress(tx, target);
      if (!progress.contactId)
        throw new ConflictException(
          'Der Manager muss zuerst seinen Kontakt auswählen',
        );
      return {
        caller: p.id,
        contactId: progress.contactId,
        accountReference: progress.contactAccountReference,
        revision: tx.state.revision,
      };
    });
    const result = await this.runtime.request(
      s,
      { issuer: a.issuer, subject: a.subject, expiresAt:a.expiresAt, membershipId: candidate.caller },
      'contact',
      { contactId: candidate.contactId },
    );
    const fresh = await this.actor(s, bearer);
    return this.repository.transact(s, async (tx) => {
      const p = this.principal(tx, fresh);
      if (
        p.id !== candidate.caller ||
        p.state !== 'operational' ||
        !['owner', 'main-manager'].includes(p.role)
      )
        throw denied();
      this.checkRevision(tx, candidate.revision);
      if (result.accountReference !== candidate.accountReference)
        throw new ConflictException('Bexio-Konto wurde geändert');
      return { ...result, onboardingRevision: tx.state.revision };
    });
  }
  async run(s: Scope, bearer: string, action: SetupAction, body: unknown) {
    const schemas = {
      provisioning: z.strictObject({}),
      settings: z.strictObject({}),
      'save-settings': z.strictObject({
        expectedRevision: revision,
        expectedHash: z.string().min(1).max(128),
        patch: z.record(z.string(), z.json()),
      }),
      bexio: z.strictObject({}),
      'bexio-configure': z.strictObject({
        clientId: z.string().trim().min(1).max(16384),
        clientSecret: z.string().min(1).max(16384),
        accountReference: z.string().trim().min(1).max(128),
      }),
      'bexio-start': z.strictObject({}),
      'bexio-finish': z.strictObject({
        code: z.string().min(1).max(8192),
        state: z.string().min(1).max(8192),
      }),
      contacts: z.strictObject({
        query: z.string().trim().max(100).default(''),
        page: z.number().int().min(1).max(1000).default(1),
      }),
      contact: z.strictObject({ contactId, expectedRevision: revision }),
      verify: z.strictObject({}),
    };
    if (
      !Object.prototype.hasOwnProperty.call(schemas, action) ||
      action === 'verify' ||
      action === 'provisioning'
    )
      throw new BadRequestException('Ungültiger Einrichtungsschritt');
    const input = parse<unknown>(schemas[action], body) as Record<
        string,
        unknown
      >,
      a = await this.actor(s, bearer);
    const captured = await this.repository.transact(s, async (tx) => {
      const p = this.principal(tx, a);
      this.eligible(tx, p);
      if (
        [
          'save-settings',
          'bexio-configure',
          'bexio-start',
          'bexio-finish',
        ].includes(action) &&
        p.role !== 'owner'
      )
        throw denied();
      if ('expectedRevision' in input)
        this.checkRevision(tx, input.expectedRevision);
      return { id: p.id, revision: tx.state.revision };
    });
    const { expectedRevision: _, ...runtimeInput } = input;
    void _;
    const result = await this.runtime.request(
      s,
      { issuer: a.issuer, subject: a.subject, expiresAt:a.expiresAt, membershipId: captured.id },
      action,
      runtimeInput,
    );
    const fresh = await this.actor(s, bearer);
    return this.repository.transact(s, async (tx) => {
      const p = this.principal(tx, fresh);
      this.eligible(tx, p);
      if (
        fresh.subject !== a.subject ||
        fresh.issuer !== a.issuer ||
        p.id !== captured.id
      )
        throw denied();
      if (['save-settings', 'contact'].includes(action)) {
        this.checkRevision(tx, captured.revision);
        const state = this.state(tx),
          progress = { ...this.progress(tx, p) };
        if (action === 'save-settings') {
          const settings = result.settings as { hash?: unknown } | undefined;
          if (typeof settings?.hash !== 'string')
            throw new ServiceUnavailableException(
              'Gespeicherte Einstellungen nicht bestätigt',
            );
          progress.settingsHash = settings.hash;
          progress.step = 'bexio';
        } else {
          const contact = result.contact as { id?: unknown } | undefined;
          if (
            contact?.id !== input.contactId ||
            typeof result.accountReference !== 'string'
          )
            throw new BadRequestException('Bexio-Kontakt nicht gefunden');
          progress.contactId = input.contactId as number;
          progress.contactAccountReference = result.accountReference;
          progress.confirmedBy = p.role === 'owner' ? p.id : undefined;
          progress.step = 'review';
        }
        state.progress[p.id] = progress;
        tx.state.lastEvent = {
          action: 'onboarding.' + action,
          actor: p.subject,
          resource: p.id,
        };
        return { ...result, ...this.view(tx, p, true) };
      }
      return { ...result, ...this.view(tx, p) };
    });
  }
  async confirm(s: Scope, bearer: string, body: unknown) {
    const input = parse(
        z.strictObject({
          membershipId: z.string().min(1).max(128),
          contactId,
          expectedRevision: revision,
        }),
        body,
      ),
      a = await this.actor(s, bearer);
    const caller = await this.repository.transact(s, async (tx) => {
      const p = this.principal(tx, a);
      if (
        p.state !== 'operational' ||
        !['owner', 'main-manager'].includes(p.role) ||
        !tx.state.onboarding?.ownerCompletedAt
      )
        throw denied();
      this.checkRevision(tx, input.expectedRevision);
      return p.id;
    });
    const result = await this.runtime.request(
      s,
      { issuer: a.issuer, subject: a.subject, expiresAt:a.expiresAt, membershipId: caller },
      'contact',
      { contactId: input.contactId },
    );
    if (
      (result.contact as { id?: unknown } | undefined)?.id !== input.contactId
    )
      throw new BadRequestException('Bexio-Kontakt nicht gefunden');
    const fresh = await this.actor(s, bearer);
    return this.repository.transact(s, async (tx) => {
      const p = this.principal(tx, fresh);
      if (
        p.id !== caller ||
        p.state !== 'operational' ||
        !['owner', 'main-manager'].includes(p.role)
      )
        throw denied();
      this.checkRevision(tx, input.expectedRevision);
      const target = tx.state.principals.find(
        (p) =>
          p.id === input.membershipId &&
          p.state === 'setup-only' &&
          p.role !== 'owner',
      );
      if (!target) throw denied();
      const state = this.state(tx),
        progress = this.progress(tx, target);
      if (
        progress.contactId !== input.contactId ||
        progress.contactAccountReference !== result.accountReference
      )
        throw new ConflictException(
          'Kontaktwahl oder Bexio-Konto wurde geändert',
        );
      state.progress[target.id] = { ...progress, confirmedBy: caller };
      tx.state.lastEvent = {
        action: 'onboarding.contact-confirmed',
        actor: p.subject,
        resource: target.id,
      };
      return {
        membershipId: target.id,
        onboardingRevision: tx.state.revision + 1,
      };
    });
  }
  async complete(s: Scope, bearer: string, expectedRevision: unknown) {
    const a = await this.actor(s, bearer);
    const captured = await this.repository.transact(s, async (tx) => {
      const p = this.principal(tx, a);
      if (p.state === 'operational') return { done: this.view(tx, p) };
      this.eligible(tx, p);
      this.checkRevision(tx, expectedRevision);
      const progress = this.progress(tx, p);
      if (!progress.contactId || !progress.confirmedBy)
        throw new ConflictException('Bestätigte Bexio-Kontaktzuordnung fehlt');
      if (p.role === 'owner' && !progress.settingsHash)
        throw new ConflictException('Grundeinstellungen zuerst bestätigen');
      return {
        p: { ...p },
        contactId: progress.contactId,
        accountReference: progress.contactAccountReference,
        settingsHash: progress.settingsHash,
        revision: tx.state.revision,
      };
    });
    if (captured.done) return captured.done;
    const p = captured.p!;
    const proof = await this.runtime.request(
      s,
      { issuer: a.issuer, subject: a.subject, expiresAt:a.expiresAt, membershipId: p.id },
      'verify',
      { contactId: captured.contactId },
    );
    if (
      typeof proof.proofId !== 'string' ||
      !/^[A-Za-z0-9_-]{1,128}$/.test(proof.proofId)
    )
      throw new ServiceUnavailableException(
        'Einrichtungsprüfung nicht bestätigt',
      );
    if (
      !captured.accountReference ||
      proof.accountReference !== captured.accountReference
    )
      throw new ConflictException(
        'Bexio-Konto wurde geändert. Kontakt erneut auswählen und bestätigen.',
      );
    if (p.role === 'owner' && proof.settingsHash !== captured.settingsHash)
      throw new ConflictException(
        'Grundeinstellungen wurden geändert. Neu laden und bestätigen.',
      );
    const fresh = await this.actor(s, bearer);
    return this.repository.transact(s, async (tx) => {
      const live = this.principal(tx, fresh);
      if (live.id !== p.id) throw denied();
      if (live.state === 'operational') return this.view(tx, live);
      this.eligible(tx, live);
      this.checkRevision(tx, captured.revision);
      const progress = this.progress(tx, live);
      if (progress.contactId !== captured.contactId || !progress.confirmedBy)
        throw new ConflictException('Kontaktzuordnung wurde geändert');
      if (!tx.publishRuntime)
        throw new ServiceUnavailableException(
          'Atomare Freigabe nicht verfügbar',
        );
      await tx.publishRuntime({
        proofId: proof.proofId as string,
        membershipId: live.id,
        issuer: live.issuer,
        subject: live.subject,
        contactId: captured.contactId!,
        role: live.role,
        expiresAt:fresh.expiresAt,
        accountReference:captured.accountReference!,
      });
      const state = this.state(tx),
        at = new Date().toISOString();
      state.progress[live.id] = { ...progress, completedAt: at };
      if (live.role === 'owner') state.ownerCompletedAt = at;
      live.state = 'operational';
      tx.state.lastEvent = {
        action: 'onboarding.completed',
        actor: live.subject,
        resource: live.id,
      };
      return this.view(tx, live, true);
    });
  }
}
