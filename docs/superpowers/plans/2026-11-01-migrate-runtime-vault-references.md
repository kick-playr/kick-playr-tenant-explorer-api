# Runtime vault reference migration plan

**Goal:** Replace only the selected development tenant's embedded MongoDB/Clerk credentials and shared Redis URL with approved vault references.

**Design:** Default to dry-run. Read the existing encrypted control envelope and current pinned club-api process/tenant snapshots. Refuse absent/deleted tenants, revision/scope mismatch, missing/invalid target values or any value mismatch. Keep all values out of output. Apply requires the reviewed source digest, writes an encrypted private backup using the existing repair helper, rechecks tenant revision/lifecycle and exact envelope in a transaction, then changes only the three references. Never provision or rotate vault secrets, change tenant lifecycle/config revisions, start services, commit or merge.

- [x] Add failing tests for exact source/target equality, dry-run, scope/revision checks, idempotence, private backup ordering and concurrent modification.
- [x] Implement migration core and CLI using the existing runtime SDK, encrypted-envelope codec and backup helper.
- [x] Document preview/apply commands and safe refusal reasons.
- [x] Run full tests/build, review and a live read-only preview. Do not apply.

Verification: all 184 tests, production build and diff check pass. Independent review passed after adding explicit runtime environment/tenant identity checks. Live dry-run reports MongoDB equality, Clerk VaultValueMismatch and Redis InvalidVaultValue; readyToApply=false and applied=false. No configuration, vault values or services were changed.
