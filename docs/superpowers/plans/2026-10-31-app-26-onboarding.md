# APP-26 Manager Onboarding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Deliver the approved provisioning checklist and resumable first/additional-manager wizard without granting early operational access.

**Architecture:** Extend APP-27 memberships with durable, revisioned setup state. A bounded authenticated control-plane/runtime setup channel reuses encrypted settings and Bexio adapters; a single control-plane transaction publishes completion and grants.

**Tech Stack:** NestJS, Next Pages Router, React, TypeScript, MongoDB, Clerk and existing tenant encryption/provider adapters.

**Spec:** `docs/superpowers/specs/2026-10-31-app-26-onboarding-design.md`

## Global Constraints

- Reference prefixes: local development `workflow-local`, preview `preview`, production `prod`; suffixes `:<name>:mongo` / `:<name>:key`.
- Manual Clerk application/claims, MongoDB and key custody installation precede the first invitation. Existing bindings and key material stay intact.
- Bexio mandatory; contact creation external. Additional managers require completed owner setup and confirmed mapping.
- Do not start/restart services, provision live resources, send real email/invitations or modify live grants. No production integration/deployment.
- HSM is shown as unsupported unless a real adapter is configured and verified; never equate environment variables with HSM custody.

## Review Focus

- A suspended/revoked tenant or principal during a long provider call must never acquire authority.
- An operator changing Bexio account, settings, realm or credential invalidates prior checks.
- Retries and simultaneous browser tabs must not duplicate memberships, settings or grants.
- An unavailable setup runtime must remain actionable and blocked rather than imply completion.
- Manual steps, saved steps and server-verified steps must be distinguishable, with secret values absent from persisted wizard state and responses.

---

### Task 1: Provisioning metadata and policy

**Files:** explorer API `src/onboarding/policy.ts`, `src/onboarding/types.ts`, `test/onboarding-policy.test.ts`; explorer UI `src/components/tenant-provisioning.tsx`.

**Interfaces:** `referenceDefaults(environment, tenantId)`; `provisioningGuide(scope)` returns ordered manual steps, exact references, public snippets and required checks. Secrets never enter this model.

- [x] Write/run failing tests for three naming prefixes, invalid scopes and public-only guide.
- [x] Implement policy/guide with current Clerk audience/realm bindings and environment key names, manual environment versus unsupported HSM instructions.
- [x] Add operator checklist UI backed by status/verify actions, distinguish unverified manual progress from successful server checks.
- [x] Run policy/component tests; record results.

### Task 2: Setup runtime authentication and adapters

**Files:** main API `src/tenancy/tenant-manager-setup.ts`, `tenant-manager-setup.spec.ts`, setup composition and `tenant-workflow-application.ts`; explorer API `src/onboarding/runtime.ts`, `test/onboarding-runtime.test.ts`.

**Interfaces:** `SetupRuntime.request(scope, actor, action, input)` with a fixed configured destination; actions settings read/update, Bexio status, contact search/read and readiness. Request authentication uses a dedicated server-only 32-byte signing key, HMAC-SHA256 over exact body, fixed purpose/path, fresh nonce and a maximum 30-second lifetime. Runtime consumes nonce through durable atomic storage and reads current definition/principal. No general proxy callbacks or role headers.

- [x] Write/run failing tests for tampered/expired/replayed/cross-tenant requests and unavailable configuration.
- [x] Implement signed fixed-route transport with bounded JSON, no redirects and safe errors.
- [x] Implement setup-only composition using existing encrypted settings service, Bexio session/transport and tenant-bound storage. Check live nonrevoked membership and owner permissions at effects; no normal guard changes.
- [x] Bind readiness evidence to definition revision, saved settings hash and Bexio account/connection/credential revision. Fence reconfiguration in the control database before publication; no remote call inside retried transactions.
- [x] Wire optional disabled-by-default setup endpoint into the actual runtime composition; prove HTTP wiring and failure behavior in tests.

### Task 3: Durable onboarding and atomic completion

**Files:** explorer API `src/onboarding/service.ts`, `src/onboarding/controller.ts`, `src/invitations/{types,repository,service}.ts`, `src/{app,main}.ts`, `test/onboarding*.test.ts`.

**Interfaces:** `OnboardingService.status/save/verify/contact/confirm/complete`; use APP-27 identity ports and transaction membership state. Repository publication writes owner completion, membership promotion and unique runtime grants in one transaction.

- [x] Write/run failing tests for save/resume, stale revision, owner-only settings, additional-manager gate, contact confirmation, revocation/configuration races and exact completion retry.
- [x] Persist policy/versioned progress without credentials or bearer tokens; return actionable next step and missing prerequisites.
- [x] Perform provider checks outside transaction, then verify fenced proof/current membership within completion transaction.
- [x] Publish only existing role policy permissions, positive confirmed contact ID, revision increments and audit. Never reactivate disabled/suspended tenants.
- [x] Replace APP-27 unavailable handoff with real status; preserve safe disabled behavior when setup adapters are absent.

### Task 4: APP wizard and platform review surfaces

**Files:** APP `src/components/manager-setup.tsx`, new onboarding component/hook, `src/server/manager-setup.mjs`, `src/pages/api/manager-setup.ts`; explorer API/UI review routes and components.

**Interfaces:** extend the existing bridge's fixed action allowlist for onboarding; authenticated status routes return server-owned role, steps, revision and completion destination. Main-manager contact confirmation uses an explicit authorized action.

- [x] Write/run failing bridge and component tests for ordered steps, saved back/next, blocked owner prerequisites and completed redirects.
- [x] Implement German responsive, labeled forms, step navigation, validation/focus, loading/errors and final summary.
- [x] Keep stored provider credentials server-only; allow only a transient masked client-secret input, never persisted in wizard progress. Display manual operator prerequisites and safe connection summaries.
- [x] Add main-manager mapping confirmation/status surfaces without widening existing settings proxy allowlists.

### Task 5: Full verification and review

- [x] Run explorer API/frontend suites, main API targeted setup/crypto/settings/HTTP tests, APP bridge/component checks, typechecks and targeted lint.
- [x] Verify complementary native encrypted-runtime and control-plane completion/publication fixtures, ordinary access denial before completion, runtime grant isolation and blocked unsupported custody/runtime; report that this is not a live end-to-end acceptance run.
- [x] Fresh independent whole-branch review; fix important findings and rerun affected checks.
- [x] Record exact evidence and limits in implementation ledger and delivery notes. Leave reviewable work on isolated APP-26 branches; prior APP-27 merge authorization does not imply production release.

## Execution ledger

- Design approved by user with “go”; execute inline without repeated approval gates.
- Four existing isolated worktrees switched to `codex/app-26-manager-onboarding` from current remote development bases; primary user checkouts untouched.
- At plan creation, no product code had been written. No external resources or secrets were changed during execution.

### Implementation progress, 31.10.2026

- Policy/guide, operator UI, generated references, signed setup transport, server-verified infrastructure/SMTP receipts and pre-invitation gate implemented.
- Main API has an optional setup composition in legacy and development workflow entry points, independently pinned setup origins, actual encrypted settings/Bexio adapters, one-use OAuth and initial verified account authorization without placeholder tokens.
- Durable owner/additional-manager onboarding, reviewed contact confirmation, strict account/settings/session-expiry fences and atomic encrypted generation/grant/completion/audit publisher implemented.
- APP bridge, responsive German wizard, typed settings forms, initial OAuth client configuration and manager contact-review UI implemented.
- Fresh checks so far: explorer API69 tests; tenant frontend69 tests/typecheck/lint; main API61 focused tests/typecheck/build; APP31 existing focused checks plus4 new UI tests/typecheck/targeted lint. Further verification/review pending.
- Ruling: reuse the existing club administrator permission catalog for newly invited operational managers; keep invitation/contact-approval powers limited to owner/main-manager membership — existing APP-27 role semantics — wrong choice would broaden club business permissions, but never platform permissions. Existing active matching grants preserve their permissions.
- Ruling: immutable runtime dispatch policy/catalog installation remains a prerequisite of the existing club runtime, not user-authored arbitrary JSON. Manual operator guide and infrastructure verification explicitly require its genuine encrypted base. The wizard edits validated business settings, creates no synthetic Bexio IDs, and blocks an empty/incompatible database.
- Ruling: setup origin may be configured separately in encrypted explorer.setupRuntimes — avoids first-owner bootstrap dependence on an operational runtime grant. No environment JSON fallback is added.
- Ruling: reuse existing local development custody only; preview/prod default references are supported but no production/HSM activation is claimed without an actual compatible adapter.
- Regression sensitivity verified: removing account/settings completion comparisons makes the new changed-generation test fail; restored guards pass.
- No development services started/restarted. No real secret generated/installed, SMTP verification invoked, OAuth exchange, invitation/email dispatch, migration, grant mutation, push, merge or deployment performed by tools. All service/provider tests use deterministic fixtures.

### Final verification and review

- Control-plane API69 tests/build; tenant frontend69 tests/typecheck/lint; main API76 tests across8 targeted suites/typecheck/build; APP31 existing focused checks +4 component tests/typecheck/targeted lint passed.
- Full APP build could not pass without isolated-checkout environment configuration; missing DATABASE_URL / NEXT_PUBLIC_API_ENDPOINT and invalid undefined endpoint rewrites are recorded explicitly. No real or placeholder deployment values installed.
- Independent whole-branch review found transactional OAuth configuration authorization and expired-token resume defects. Both were reproduced with failing regressions, fixed, rerun green and independently re-reviewed with no further important findings.
- Removed unknown-tenant URI database fallback: setup and ordinary runtime must share an existing finite development storage profile. Unsupported tenants/environments/custody remain blocked.
- Review minor remains: safe setup transport errors are generic; manual prerequisites and operator verification diagnostics are documented.
- Verification is complementary deterministic native/provider/control-plane/UI fixture coverage, not live provider or replica-set end-to-end acceptance. Prior APP-27 authorization does not authorize publishing APP-26; keep isolated worktrees/branches for review.

### Authorized development integration

- User explicitly requested merge into development and an env.example documentation check. This supersedes the earlier leave-uncommitted instruction; production remains outside scope.
- Updated all four environment examples (added main API setup supplement), including key placement, exact reference names, manual prerequisites and unsupported adapters.
- Exact patch bumps: control API/frontend0.1.1→0.1.2, APP10.0.6→10.0.7, main API10.0.3→10.0.4. APP release date refreshed with release:date (31.10.2026); public version regenerated.
- Integration targets: tenant repositories development; APP/API kick-playr-development. Separate commits and PRs per repository, no production target.
