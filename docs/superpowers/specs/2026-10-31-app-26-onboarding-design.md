# APP-26: resumable manager onboarding

Status: approved by the user with “go” on 31.10.2026, including the corrected stage-specific reference names. Implementation underway.

## Intent and confirmed decisions

Give an invited manager a guided route from accepted invitation to authorized club management. APP-27 already creates the durable setup-only membership and binds it to a verified Clerk identity. Resume that membership; do not create a second club or registration.

The platform provisions the club and invites its first manager. That manager becomes the owner. The club and its Clerk workspace must already exist, and invitation email delivery must work. Bexio is mandatory. Existing Bexio contacts are created outside this wizard. Finish club setup and connect Bexio before selecting the manager contact. Additional managers cannot finish onboarding before the first manager has finished. A main manager confirms their contact mappings. Keep existing operational authentication and positive contact-ID validation.

Only Bexio is a mandatory business integration. Other providers remain optional unless enabled by an explicit server-owned club policy. Never treat every supported integration as mandatory. Verified Clerk email and live membership/session checks remain required.

## Approach

Extend APP-27's setup identity, tenant-bound bridge and separate membership state, and reuse existing settings/integration validators and adapters through a restricted setup composition. This is the sensible continuation of the agreed design. A second registration system would duplicate clubs and ownership; granting temporary operational administrator access would defeat the agreed onboarding block.

The builder chooses module names, component boundaries and internal interfaces, using existing NestJS, Next Pages Router, MongoDB, Clerk, Zod and encrypted tenant configuration. Do not introduce another auth provider or workflow service.

## User journey

### Platform provisioning before the first invitation

Add a guided, resumable operator checklist before the club-manager wizard. The operator performs the external actions manually; the application provides tenant-specific instructions, nonsecret configuration snippets and verification status. An unchecked checkbox alone is never proof of readiness.

1. **Create Clerk application/workspace manually.** Use the correct environment and register the club APP origin and redirect destinations. Record the issuer and publishable key; place the backend secret in the selected server-side secret store. Bind the provisioned tenant to that exact realm. Check the actual signed-in identity/session before allowing the first invitation. The club manager does not create the platform identity project.
2. **Configure Clerk session claims manually.** Show a copyable claim configuration derived from the actual setup and operational audience requirements. Explain where to paste it in Clerk. Configure both flows consistently; do not blindly paste the example `club-setup` audience where operational APIs expect another value. Verify a fresh session token server-side for issuer, required audience, origin/authorized party and expiry without displaying its bearer value. Roles, permissions and contact IDs continue to come from server-owned authority, not editable user metadata or a claimed administrator flag.
3. **Create MongoDB database/access manually.** Explain the separate control-plane and operational club database purposes; reuse a configured control plane rather than creating a duplicate one for every club. Guide creation of the tenant database, appropriate database users, network access and connection URI/reference. The control plane requires Atlas/replica-set transaction support. Store the URI server-side and verify connection, required access and encryption configuration. Do not silently initialize synthetic settings or broad database privileges.
4. **Generate and install tenant keys manually.** Provide the exact existing wrapping/index/control key purposes, independent per-tenant/environment values, required encoding and versioned references. Use current cryptographic generation helpers, with explicit copy/install/verify steps. Secret generation/copy is an operator action, never a shared browser log or persisted wizard field. Existing shared wrapping/configuration keys must be reused when applicable; generating replacements is not a configuration repair. Keep old key versions available for existing encrypted data and backups.
5. **Choose and validate key custody.** For the existing local/server environment path, show the exact server-only variable names and required files/services, with copy/paste installation instructions for `.env` or deployment secret variables. Never use `NEXT_PUBLIC_` for private keys or connection secrets. HSM/KMS is a distinct custody mode: configure its provider/key reference and runtime permissions, then test the actual cryptographic adapter. A non-exportable HSM key is created inside the provider, not copied into `.env`. An ARN/reference or secret-manager environment variable alone is not evidence of HSM integration. The current environment/key-file implementation must not be presented as a working HSM adapter. Unsupported custody remains visibly blocked until the adapter is implemented and verified.
6. **Verify routing and email, then invite.** Check tenant hostname/runtime binding, Clerk configuration, MongoDB, required keys and platform invitation sender readiness. Show exact missing prerequisites and which operator must fix them. Only then issue the existing APP-27 invitation; do not send one merely to test the checklist.

Persist nonsecret references, progress and server verification results in the control plane so another operator can resume. Mask secret inputs and do not echo stored values. Recheck results after relevant changes. The manual provisioning checklist and the manager wizard are two stages of the same onboarding status; completion of the operator checklist does not activate the club or grant manager operational access.

Reference naming confirmed by the user: for local development, prefill `workflow-local:<name>:mongo` and `workflow-local:<name>:key`; for preview, `preview:<name>:mongo` and `preview:<name>:key`; for production, `prod:<name>:mongo` and `prod:<name>:key`. The reference prefix `prod` maps to the existing environment value `production`; do not rename that environment enum. A read-only check of the current development control database confirmed FCRWW uses `workflow-local:fcrww:mongo` and `workflow-local:fcrww:key`. Preserve configured references when resuming an existing tenant. These defaults do not authorize renaming existing bindings or replacing key material. Test-environment naming remains an implementation decision unless separately specified.

### Club manager after invitation acceptance

1. **Verein und Zugang:** load the provisioned club, identity workspace and manager membership. Show immutable club identity and verified signed-in account. Explain any platform prerequisite that needs operator action. Do not let the user create or select an arbitrary tenant.
2. **Grundeinstellungen:** owner edits the existing club settings schema, with section-level validation and server-saved progress. Reuse current required business fields and date/season validation, never invented synthetic defaults. Branding and currently optional fields stay optional. Additional managers see the completed club summary and cannot edit global setup through this wizard.
3. **Bexio verbinden:** owner connects or verifies the configured club Bexio account through existing credential/OAuth mechanisms. Display connection status and account identity, never credentials. Existing valid configuration can be reused after verification. Missing runtime provisioning yields an actionable blocked state, not a fake successful check.
4. **Kontakt zuordnen:** read existing contacts only from the verified Bexio account. Owner selects their own positive contact ID. For additional managers, a main manager confirms the mapping through an authorized review action. Never infer contact identity from a typed ID alone or expose an unrestricted contact export. Search is paginated and limited to fields needed to identify the contact.
5. **Prüfen und abschliessen:** show club, settings, Bexio account and confirmed manager contact. On explicit completion, revalidate prerequisites and atomically publish completion and runtime authority. Show success and a link to club management. Returning completed managers go directly to management when their current authority remains valid.

All screens show progress, next/back navigation, loading states and actionable validation errors. Save valid steps server-side before advancing; back navigation and refresh retain saved values. Unsaved edits stay in the current page and are visibly marked. Provide a summary of validation errors with focus management, visible labels and keyboard-accessible mobile layouts. Use German UI text consistent with the APP.

## Authorization and integration boundary

Every setup action derives tenant/environment from the validated binding and verifies the live Clerk session plus current invitation principal. A setup-only identity can read its own setup status, save permitted onboarding fields and perform the specific provider/contact actions allowed for its role. It cannot call general operational APIs, alter tenant routing/realm/secret references, grant permissions or choose its own role.

Existing runtime settings routes require operational grants, so simply proxying them creates a bootstrap deadlock. Add a separate server-owned setup composition in the main API that reuses tenant settings and provider services without weakening their normal guards. It accepts only tightly scoped authenticated control-plane requests bound to tenant, environment, actor, action, request body and expiry. Use replay protection for writes. Keep destination hosts server-configured; no arbitrary URLs, forwarded role headers or browser-supplied capabilities. Provisioning/configuration failures stay explicit. The implementation plan must specify and test the concrete authentication contract before writing this transport.

The Bexio adapter verifies the selected account and reads the selected existing contact using that account's configured credentials. Provider checks occur outside retried MongoDB transactions. Proof is short-lived and bound to the exact tenant, environment, membership, definition revision, provider account and connection/credential revision. Reconfiguration invalidates proof. A server-side setup-policy version identifies which required checks were passed.

## Durable state and publication

Keep one onboarding document per environment/tenant, with per-membership progress, server-owned policy version, optimistic revision, selected contact, confirmation actor, completed steps and timestamps. Use deterministic tenant keys; retries cannot create clubs, invitations or memberships. Never store provider credentials, raw invitation tokens or Clerk bearer tokens in wizard state.

The control-plane repository owns one completion publisher. Its transaction rereads and fences the current definition, authority, owner, nonrevoked principal, saved settings/proof and expected revisions. It rejects disabled/suspended tenants, stale account/configuration, expired proof, changed mappings and concurrent revocation. For the first manager it records tenant setup completion and publishes the owner runtime grant with the existing administrator permission policy. For an additional manager it requires completed first-manager onboarding plus main-manager mapping confirmation and publishes only that manager's allowed role permissions.

Completion, principal promotion, runtime authority updates and audit record commit atomically. Increment relevant authority/support revisions. Exact retries return the recorded completion without duplicate grants. Concurrent changes conflict safely and require refresh. Never reactivate a deliberately disabled/suspended tenant or restore revoked authority as a side effect. Provisioning-to-active is allowed only for the authenticated first-owner completion when all required checks hold; already-active tenants keep their lifecycle status. Account/realm/config changes after completion invalidate stale evidence and follow existing access-revocation rules.

## Scope and exclusions

Implement the real setup transport/adapters, persisted wizard, readiness checks, confirmed mappings, completion publisher, APP-27 handoff and returning-manager routing. Extend tenant explorer only where the existing platform/main-manager review surface needs status or mapping confirmation. Preserve the existing settings editor and operational routes.

Do not implement public self-service club creation, Bexio contact creation, owner transfer/recovery, unrelated provider setup, bulk imports or production rollout. Do not send real invitations, emails or alter live grants while testing. Do not start or restart development services. User approval of the code integration is separate from configuring a live club or completing onboarding on someone's behalf.

## Verification and acceptance

Use service/repository tests for tenant isolation, live identity checks, role restrictions, save/resume, stale revisions, account replacement, contact verification, additional-manager gating and atomic/idempotent publication. Test the actual setup HTTP authentication, replay/expiry/forged-request denial and composition wiring. Include failure cases at each provider/persistence boundary; no network calls inside retried transactions.

Test APP bridge allowlists, redirect behavior, keyboard/mobile wizard navigation, loading/error states and saved back/next navigation. Verify ordinary operational access remains denied before completion and works only for the correct tenant/member afterwards. Run appropriate existing test suites, builds/typechecks and targeted lint in each touched repository. Separate deterministic fixture coverage from live-provider checks; report any unavailable live verification explicitly.

## Approval boundary

This design preserves the previously confirmed ordering and blocking rules. It proposes reusing current required settings rather than inventing a second field checklist, and a restricted setup composition rather than a temporary administrator grant. Architecture/security review and user design approval precede product implementation, as requested by the story and brainstorming workflow.
