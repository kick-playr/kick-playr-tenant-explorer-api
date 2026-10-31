# APP-27 invitation boundary

Scope approved in Jira comments 10035–10038. This feature delivers invitation management, verified acceptance, a separate setup principal and a blocked APP-26 handoff. It never inserts incomplete runtime authority users, activates tenants or exposes a completion bypass. Existing runtime positive `contactId` validation is unchanged.

Configure `EXPLORER_INVITATION_BINDINGS_JSON` with exact environment/tenant, expected Clerk issuer, APP origin, audience, authorized origins and secret-key environment-variable name. Configure the existing platform Clerk secret too: new invitation routes additionally check live operator session/user. Configure a dedicated SMTPS invitation sender and from-address; absent sender prevents creation. No environment values or real invitations were installed by this change.

APP requests a Clerk session token (optionally a dedicated template) carrying the configured `aud`, session `sid`, issuer, subject, `azp`, `exp` and `nbf`. Every setup request checks the live session and user. All currently verified emails qualify; matching does not rewrite plus/dot aliases. Known subjects use exact server-side tenant Clerk lookup. No directory search is exposed.

A link is `/invitations#<opaque-token>` on the configured APP origin. Fragment tokens avoid HTTP query/access-log leakage. APP captures into a host-bound encrypted HttpOnly cookie, removes the fragment and preserves context through normal registration/sign-in. Operations require explicit acceptance. Wrong recipient/realm, expired/revoked link or revoked principal fails closed.

## Persistence and delivery

`tenantManagerInvitations`, one `_id=environment/tenant` document, stores invitations, separate principals, bootstrap owner reservation and revision. Built-in Mongo `_id` uniqueness suffices; no index migration runs. Transactions read current definition+authority, write a definition `invitationFence` without altering runtime configuration/grants and store changes with snapshot/majority semantics. Minimal audit events omit tokens/email content. Persisted limits of 10 mutations/minute per inviter and 60/minute per tenant supplement HTTP per-IP throttling. Max 128 retained invitation records per tenant bounds document size; retention beyond that requires an explicit reviewed archive process.

Pending tokens have a SHA-256 verifier and an AES-GCM-encrypted delivery envelope bound to tenant/environment/invitation/version. `POST .../:id/deliver` is a bounded durable-outbox attempt (five attempts per version, 60-second claim lease). UI calls it after create/resend; queued/failed intent survives browser interruption and can be retried manually. No background worker is started. Retrying uses the same link/message ID; SMTP timeout is uncertain delivery, not exactly-once mail. Explicit resend rotates/invalidate links. Delivery accepted means SMTP acceptance, not confirmed recipient delivery. Revoke can invalidate a link even after delivery was claimed.

Platform manages bootstrap; main managers need explicit persisted operational owner/main-manager evidence AND a current active runtime user. This feature cannot promote roles or activate a principal. Existing unpublished club administration is not a dependency.

## APP-26 dependency

Status returns setup-principal ID, tenant/environment, `membershipState`, blocked state, revision, `policyVersion:null`, `nextStep:null`, `missingPrerequisites:["app26-unavailable"]` and `operationalAccess:false`. APP shows a resumable saved invitation and blocked setup, not a fabricated wizard. There is no `/finish` or `/activate` endpoint. APP-26 must own its approved checklist and a single control-plane publisher that atomically records completion + positive-contactId runtime grants, fenced to current Bexio account/configuration and live membership. No provider network call inside a retried Mongo transaction.

Bexio is mandatory for activation; contacts are created outside the wizard. Bootstrap owner selects existing own contact after Bexio proof; main managers confirm additional mappings. Those provider setup/mapping adapters and runtime publication are reserved to the actual APP-26 composition: no available published composition accepts setup-only identities today. This PR intentionally reports that gap rather than weakening runtime guards or copying unpublished local work. Full registration-to-operational onboarding is not delivered or E2E verified.

Unit/HTTP tests use isolated in-memory/native-driver doubles and do not start persistent services, deliver mail, change real grants or contact providers. Real Mongo transaction/SMTP/Clerk browser integration needs separate authorized QA against the exact PR SHA.

## Accepted-access revocation and owner recovery

`revoke-access` is distinct from revoking a pending invitation. It atomically revokes the setup principal and, when present, the exact issuer+subject runtime grant, increasing authority/user revisions without changing contact mapping. No grant is created. Acceptance replay cannot restore access. Main managers cannot revoke the bootstrap owner; platform can revoke compromised owner access.

The accepted owner relation is immutable in approved APP-27 scope. Revoking that owner deliberately blocks setup; automatic ownership replacement/restoration is NOT provided. Recovery/transfer requires a separately approved process. This preserves the no-owner-transfer requirement in SABB10036/10038 rather than creating an unapproved takeover path.
