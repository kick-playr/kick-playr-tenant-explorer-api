# APP-29 controlled tenant deletion

## Approved product behavior
Normal deletion blocks tenant access and retains data for three calendar months (Europe/Zurich, clamped end-of-month). An explicit permanent deletion action is available anytime, including before that period ends. It requires the manual cleanup checklist, a final checkbox confirming all cleanup is complete, and typing the exact environment/tenantId. Expiry never bypasses this confirmation. Recovery is limited to the recovery period and restores a disabled tenant; grants must be reviewed before reactivation.

## UX
A separate danger section in the platform tenant Overview opens an accessible dialog. It shows tenant identity, environment, domains, impact and retained versus cleanup resources. Confirmation is bound to current configuration/authority revision. Deleted tenants remain discoverable and read-only with recovery deadline, checklist and persistent purge operation progress. Stale revisions require reloading impact and retyping. A lost response is reconciled by reading operation status, never by assuming success. Partial cleanup is retryable under the same operation.

Manual checklist: verify ownership; revoke memberships/service/API access and invitations; stop schedules and reconcile inflight/external work; remove retained external files/backups under the chosen policy; disconnect provider accounts without touching shared data; remove exclusive Clerk resources; remove DNS/certificates/bindings; clear caches and runtime copies; verify all manual cleanup complete. Databases remaining for automatic deletion are described separately; the checklist must not require operators to erase databases before the automatic action.

## Architecture/security constraints
Platform administrator backend authorization is mandatory. Tombstones prevent ordinary lifecycle edits, invitation acceptance or setup from reactivating a deleted tenant. All lifecycle changes use existing transaction/revision fences; revoke tenant grants and pending invitations in the lifecycle transaction. Keep IDs/domains reserved during retention and until explicit verified cleanup; preserve only a minimal final tombstone/audit after purge.

Purge may act only on server-owned verified targets, never database names/URIs supplied by a browser. Shared control-plane records use exact environment/tenant scope. Dropping a database requires exclusive ownership proof and protection against reassignment. Missing or unverified inventory fails closed and is visible. Inventory includes encrypted runtime configuration and all registered tenant database bindings; manually cleared caches/provider resources remain explicit attestations. Do not infer exclusive key, Clerk, cluster, account or domain ownership from a name. Inflight work already sent externally requires reconciliation, not a claim of instant recall.

Persistent operation identity, manifest binding and idempotent steps protect retries after partial success. An interrupted purge must not be recoverable/reactivatable. Failure is recorded safely without secrets. Minimal audit is exempt from data purge; no new audit-retention duration is invented.

## Approaches
Chosen: reversible access-blocking deletion followed by explicit confirmed purge with verified owned resources and manual external cleanup. Immediate erase alone does not provide the approved recovery period. Silent scheduled purge conflicts with mandatory final checklist confirmation.

## Delivery
Feature branches codex/app-29-delete-tenant in isolated Explorer/API worktrees based on origin/development; no primary changes copied. No real tenant deletion, key revocation, migrations, service starts/restarts, deployment or production/main merge during delivery. Fixture-only verification. Chris must explicitly approve architecture/security before Jarvis implementation; Trip independent QA before Lolo review. Fresh bases: Explorer 71cf78869c5503ea197bcd95555456a841c2e1b3; API 422ab38c264e420474b070133106270405b59222.

## Review decisions
Chris SABB/security explicitly approved implementation with fail-closed complete server inventory, atomic revocation/fencing and durable verified cleanup. Trip reproduced and then verified a fix for target reassignment: target reservations share a transactional write fence with Mongo runtime assignment, persist through failure/purge, and are checked before/after connecting and in finalization. AllDone attests manual external cleanup only; automatic database erasure still requires server verification.
