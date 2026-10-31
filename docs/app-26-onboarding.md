# APP-26 manager onboarding

The platform provisions the existing club before inviting its owner. In the tenant editor, **Onboarding** shows six manual preparation steps, existing/default references, Clerk claims and private environment-variable names. A saved checkbox is an operator acknowledgement, not a successful connection test. **Verbindungen prüfen** performs setup API/key/database/runtime-base checks and an SMTP connection verification without sending email.

## Reference names

| Environment | MongoDB reference | Key reference |
| --- | --- | --- |
| Local development | `workflow-local:<name>:mongo` | `workflow-local:<name>:key` |
| Preview | `preview:<name>:mongo` | `preview:<name>:key` |
| Production | `prod:<name>:mongo` | `prod:<name>:key` |

Existing FCRWW references remain `workflow-local:fcrww:mongo` and `workflow-local:fcrww:key`. Reference prefixes do not rename environment enum values; production remains `production`.

## Manual provisioning

1. Create the club Clerk application, configure its origins/redirects and install its public/private values in the existing server configuration. Configure the session `aud` claims shown by the guide; local runtime audience is `kick-playr:development:<name>`. The guide includes the separately configured invitation audience too. Standard Clerk subject/session/issuer/expiry claims must stay intact. Sign in again after changing claims. Application roles/contact IDs are not editable Clerk claims.
2. Create the operational database and users/network access on the configured cluster. Install the existing tenant runtime's encrypted settings, catalogs and genuine club-specific dispatch policy using the normal runtime provisioning process. This wizard does not invent Bexio IDs, business policy, settings fixtures or assets. A blank database is not a provisioned club. Atomic completion currently requires operational/control databases reachable through the same configured native MongoDB cluster/client.
3. Generate separate 32-byte wrapping, index and control keys and install them under the guide's configured variable names; keep existing keys and versions intact. Use server-only `.env`/deployment secret variables. No private value belongs in `NEXT_PUBLIC_*` or wizard progress.
4. Configure a separate `MANAGER_SETUP_CONTROL_KEY` (32 bytes, canonical base64) on the control-plane API and main API. Do not reuse any tenant, vault or root wrapping key. Example local generation command: `node -e "process.stdout.write(require('node:crypto').randomBytes(32).toString('base64'))"`. Generate/install manually; never commit the generated value.
5. Configure the setup API destination. Encrypted `explorer.setupRuntimes` optionally specifies `{ environment, tenantId, origin }`; it is independent of ordinary `clubRuntimes`. This allows first-owner setup to use the main API's setup composition before ordinary runtime authorization exists. If omitted, the existing club-runtime origin is used. Origins are fixed server-side and validated; no browser URL or connection string is forwarded.
6. Configure the existing platform SMTPS invitation sender. Verify infrastructure before the first invitation; a fresh matching receipt is required. SMTP verification confirms connection/authentication, not mailbox delivery. Live Clerk audience/session/email verification occurs when the invited manager signs in.

The installed setup key-custody adapter is the existing development environment implementation. Tenant database/key bindings now come from the authenticated encrypted runtime manifest. Additional registered tenants such as DEMO no longer require a per-club code change; their genuine URI, Clerk/key references, policy and provisioned base are still mandatory. Preview/production references are generated correctly, but setup fails closed without a verified compatible custody/runtime adapter. HSM/KMS references are not treated as working HSM support; non-exportable keys must stay inside a real provider adapter.

## Manager flow

Accepted APP-27 invitations lead to `/onboarding`. The owner confirms the club, saves base settings, connects/verifies Bexio, selects an existing own contact and completes a summary. Initial OAuth client credentials can be installed from the Bexio step; they are encrypted in dedicated provider configuration, never stored in wizard progress. First OAuth completion verifies the Bexio company before publishing an active connection; no placeholder access token or pre-existing active connection is needed. Disabled/suspended connections are not revived. Expired access tokens use the existing durable refresh reservation before the verification generation is pinned; uncertain refresh outcomes require reconciliation and are never blindly replayed.

Additional managers remain blocked until the owner completes. They select an existing Bexio contact; an operational owner/main manager reviews its live name/account in `/managers` and confirms the mapping. The selected contact needs the club's configured Bexio administrator branch for operational manager access. Contacts are created/updated outside the wizard.

Progress is server-side and revisioned. Back/next retains page drafts; valid settings save before advancement. Returning completed managers are redirected to the club. Concurrent settings/account changes, revocation and expired sessions prevent publication. A fresh verified request cannot extend the original Clerk token expiry.

## Completion boundary

No ordinary guard is weakened. A dedicated HMAC capability signs a fixed setup route, exact scope/actor/action/body, nonce and a lifetime bounded by both 30 seconds and caller authorization expiry. The main API consumes nonces durably and checks current setup membership before effects. Fixed adapters reuse actual tenant encryption/settings/Bexio services.

Provider checks run outside retried transactions. Completion reads fresh short-lived proof and transactionally replaces exact observed settings/Bexio encrypted generations with freshly authenticated ciphertext, providing real write locks rather than no-op read fences. The same transaction publishes runtime authority, owner completion, principal promotion, proof consumption and audit. Positive contact validation and existing grants remain intact; identical active grants can be adopted without changing their permissions. New grants use the existing concrete club administrator permission catalog; invitation/contact approval still requires owner/main-manager membership. Disabled/revoked grants require explicit reconciliation.

Collections are created only when authorized operations actually persist state. No startup migration, development service, invitation dispatch, live grant or production deployment is run by this implementation task. Verification uses deterministic fixtures; live provider/deployment acceptance is separate.

## Verification record, 31.10.2026

- Control-plane API: 69 tests and TypeScript build passed.
- Tenant frontend: 69 tests, typecheck and lint passed.
- Main API: 76 targeted tests across eight suites, typecheck and build passed, including durable refresh coverage. Regression tests demonstrated failure before the fixes for transactional OAuth authorization and expired-token resumption; both now pass.
- APP: 31 existing focused checks plus four wizard/review component tests, typecheck and targeted lint passed. Full Next build is blocked by missing isolated-checkout environment configuration (`DATABASE_URL`, `NEXT_PUBLIC_API_ENDPOINT`); skipping schema validation still correctly fails invalid endpoint rewrites. No placeholder deployment values or real secrets were installed.
- Fresh independent review covered all four repositories; both important findings were fixed and reviewed again. No further important findings were identified. Safe setup errors remain deliberately generic; operator guidance provides prerequisite diagnostics.
- Coverage combines the actual encrypted native runtime fixture, protocol/HTTP checks, control-plane completion/publication fixtures and UI/bridge tests. It is not a live Clerk→SMTP→Bexio→MongoDB replica-set acceptance run. No development service was started/restarted.

The implementation was reviewed on isolated `codex/app-26-manager-onboarding` branches before the separately authorized development integration. Environment examples in all four repositories document the relevant variables/manual prerequisites; the main API now includes a setup-specific `.env.example`. Versions for development integration: control-plane API/frontend0.1.2, APP10.0.7, main API10.0.4. No production merge, real invitation, OAuth exchange or grant publication is part of that integration.

## Database-driven registration follow-up

The runtime now loads tenant IDs and explicit operational database paths from authenticated encrypted `tenants[]` metadata, and the explorer derives key bindings from the same rows. Registering a new tenant no longer requires changing a fixed club list. Existing scope/cluster/database isolation and active-authority checks remain enforced. Real MongoDB/Clerk/policy metadata and provisioning are still required; this change does not add a URL-entry UI or invent DEMO configuration.

Development integration versions: tenant API0.1.3 and runtime API10.0.6. Companion tenant/application frontends already contain APP-26 and have no pending changes. The tenant API key-generation helper is included as edited in the primary checkout.
