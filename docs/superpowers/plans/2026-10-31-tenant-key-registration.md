# Independent tenant key registration

User approved a Configure tenant keys step independent of complete runtime registration. Explicit WORKFLOW_REAL_<TENANT> variable names derive from the tenant's database-owned workflow-local:<id>:key reference. No arbitrary variable names or raw keys enter browser input.

- [x] Add a platform-only signed key-check action before operational-resource lookup. Derive names from trusted existing mapping/runtime row or the standard new-tenant convention. Return challenge HMAC attestations bound to tenant/environment/reference/config revision/kind/variable/expiry, never key values. Reject missing/invalid/reused keys and unsupported stages. Preserve nonce/deadline/current-platform checks.
- [x] Control API reads local keys, checks independent valid32-byte values, obtains remote attestations outside transactions and verifies both APIs agree. Save only variable mapping in the encrypted explorer key registry, with whole-envelope CAS and existing tenant/authority/readiness/audit fences. Gate to uninvited provisioning tenants, reject races/expiry/conflicts and never rotate existing encrypted-data keys.
- [x] Reuse the existing encrypted-configuration transaction boundary for Mongo URL and key updates. Refresh key metadata from the database on reads so saves work without API restart or a full tenants[] runtime row.
- [x] Add a button/statuses in onboarding, update all shared configuration/setup revisions after a save and preserve secret-free messages. Do not present key registration as full infrastructure readiness or activation.
- [x] Tests first: protocol/vector/scoping/platform-only route without resources; missing/mismatched/reused keys and stale/expired proofs; atomic metadata save/no secret persistence; immediate refreshed status; UI/proxy; existing Mongo URL behavior. Build/type/lint, fresh independent review and docs.

Scope: existing local development custody only. One-time platform signing key remains preconfigured. No live keys/configuration writes, service starts/restarts, version bump, commit/push/merge or runtime activation in this implementation turn.

## Verification

- Tenant API: 107 tests passed; TypeScript production build passed.
- Tenant UI: 90 tests passed; typecheck and ESLint passed.
- Runtime API: 27 related tests across 7 suites passed; whole-source TypeScript check passed.
- Fixed protocol vector matches in both APIs; regression coverage includes existing-instance registry refresh and supported explorer-only encrypted envelopes.
- Independent reviewer found an explorer-only read regression; fixed with red/green regression test, then reviewer verified no remaining blocker.
- Git diff whitespace checks passed in all three repositories.

No live secret or database mutation, service restart, runtime activation, version bump, commit, push or merge was performed. Changes remain isolated on codex/tenant-key-registration in all three repositories. Offline tests do not establish a deployed Clerk/provider or real Mongo transaction round trip.
