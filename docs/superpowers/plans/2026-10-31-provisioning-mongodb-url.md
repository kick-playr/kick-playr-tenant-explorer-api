# Provisioning MongoDB URL editor

User requested entering the real tenant MongoDB URL in the provisioning UI and saving it encrypted. Implement inline in existing isolated worktrees; no live configuration writes/service restart/automatic integration.

- [x] Add shared runtime-envelope read/write codec compatible with existing AES-256-GCM/AAD format. Preserve the whole decrypted payload when replacing it; no private projection is returned.
- [x] Add live-platform-authorized fixed POST onboarding/mongo-url and sanitized GET status. Strict body/scope/URI checks, same runtime cluster/authentication, explicit distinct non-system database, no network call to the entered URI. Encrypted envelope CAS, tenant definition write fence, invitation-state/authority checks and audit are one native majority snapshot transaction. Expiry rechecked in every callback. Reject active/suspended/invited tenants; invalidate any provisioning receipt.
- [x] Existing registered tenant updates its encrypted tenants[].mongoUri. Unregistered tenant stores a scoped pendingMongoBindings[] draft inside the same envelope, without fake Clerk credentials/policy/grants. Runtime loader recognizes but never activates these drafts. Development adapter only; unsupported stages remain visibly unavailable.
- [x] Add masked UI field, no readback, save/loading/error states, clearing transient input after submission, configured-vs-draft status and reload/pending-registration explanation. Extend proxy allowlist only for the fixed route.
- [x] Tests first for encryption/preservation/CAS/isolation/expiry/invitation gate/URI validation/no secret response, UI submission/input clearing/errors/proxy scope. Test actual controller authorization/wiring. Run affected suites/build/type/lint; independent code review; document prerequisites and limits.

## Verification ledger

- Shared codec compatibility test and new-tenant encrypted-write tests failed before implementation, then passed. Readiness race regression reproduced acceptance of an obsolete check before setup-revision comparison was added.
- Final checks: tenant API91 tests/build; tenant frontend87 tests/typecheck/lint; runtime18 targeted tests/typecheck/build. Shell/native tests made no live provider/configuration writes.
- Fresh independent review found no confirmed blockers after tracing actual dynamic setup-resource lookup. Added regression showing each signed setup request resolves fresh resource mapping and rejects an unprovisioned replacement database.
- Late authorization expiry after encrypted write is covered by native-transaction contract rollback tests. Fixtures are not a live replica-set acceptance run.
- Documentation: docs/provisioning-mongodb-url.md. Changes remain uncommitted in three isolated codex/provisioning-mongodb-url branches. No version bump, push, merge, service restart or live URL installation performed.

## User-requested checklist refinement

- Structured public guide descriptions/actions and a reusable accessible checklist replace repeated headings/checkbox labels. Existing progress persistence and old-guide fallback preserved.
- Final follow-up checks: tenant API91 tests/build; frontend88 tests/typecheck/lint. Static real-component Chrome rendering verified all six rows in desktop, mobile and dark themes: right-side22px checkboxes, no title overlap or horizontal overflow. This did not start a development service or use live tenant data.
- Preview screenshots: /tmp/provisioning-checklist-desktop.png and mobile viewport previews. Changes remain uncommitted with the URL-editor feature.

## Shared setup key placement

- User requested shared MANAGER_SETUP_CONTROL_KEY setup only once before tenant creation. Removed its generation/install action, generated tenant snippet entry and tenant-facing error reference. Kept the actual platform requirement unchanged and documented it separately as one-time platform bootstrap. Per-tenant wrapping/index/control keys remain tenant-scoped.
- Regression checks cover absence from guide/snippet; tenant API93 tests/build and frontend88 tests/typecheck/lint passed. No key or live configuration changed.

## Authorized development integration

- User requested Merge. Include all pending URL-editor, checklist and one-time shared-key documentation changes. Targets: runtime kick-playr-development (10.0.7), tenant API development (0.1.4), tenant frontend development (0.1.3). Application frontend is already current and has no pending changes.
- Exact patch bumps applied once per changed repository; APP-owned release date refreshed and already current at31.10.2026.
- Merge runtime draft compatibility before API writer/frontend. No production merge, live URL installation or manual service restart is included.
