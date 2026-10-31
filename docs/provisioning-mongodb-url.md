# MongoDB URL in tenant provisioning

Open a tenant in the explorer and select **Onboarding → MongoDB-Verbindung**. Enter the full MongoDB connection URL, including the tenant database path, into the masked **MongoDB-URL** field and select **MongoDB-URL verschlüsselt speichern**.

The field is write-only: stored usernames/passwords are never returned to the browser. Input is cleared after submission, including failures. Status distinguishes an existing runtime binding from a saved preparation draft. Saving validates format and ownership but does not connect to the entered URL or certify database readiness.

## Storage and prerequisites

The API uses the existing `WORKFLOW_SHARED_WRAPPING_KEY_V1` to reseal the entire `tenantWorkflowConfiguration/runtime:development` envelope with the compatible AES-256-GCM/AAD format. No new environment variable or key rotation is required. Existing unrelated configuration is preserved.

- For an existing runtime tenant, update its `tenants[].mongoUri`.
- For a tenant such as DEMO without complete runtime registration, save `{ tenantId, mongoUri }` in encrypted `pendingMongoBindings[]`. This draft is not an operational binding. Genuine Clerk credentials, environment key references, runtime policy, control records and encrypted operational base still need registration/provisioning. Do not invent placeholder credentials or grants.
- The runtime loader recognizes drafts and never loads their database or activates their tenant. Its compatible change must ship together with the writer before using drafts.

The current adapter supports development. The tenant must still be provisioning, have no manager invitations, principals, owner, user/service grants or active runtime authority. Active/suspended or already invited tenants cannot redirect their database through this form. The URL must use the configured runtime's cluster/authentication/TLS/authSource and a distinct explicit non-system database, separate from the control database and other registered/draft tenants.

## Save boundary

`POST /api/platform/tenants/:environment/:tenantId/onboarding/mongo-url` accepts exactly `{ uri, expectedRevision }`. Live platform Clerk authentication is required. The same-origin frontend bridge only permits this fixed route. Provisioning GET returns sanitized `mongo` status, source, encrypted configuration revision and editability; never a stored URL.

The native snapshot/majority transaction compares the exact observed encrypted envelope, takes real tenant/authority write fences, clears readiness, advances the invitation setup revision (creating it if absent) and writes a secret-free audit event. Concurrent changes produce a conflict. Authorization expiry is checked again before commit. Infrastructure verification compares setup revision across its external checks, so an old in-flight check cannot restore invalidated readiness.

The configured setup adapter rereads its encrypted resource mapping on each signed request. Ordinary running workflow configurations remain startup snapshots; operators reload affected APIs after completing registration/configuration. No service was started/restarted or live URL installed by this implementation task.

## Verification

Deterministic coverage includes envelope compatibility/tampering, ciphertext preservation and CAS, native transaction rollback/expiry, invitation/grant gates, duplicate/system/foreign-cluster database rejection, readiness races, masked UI/input clearing, parent revision updates, same-origin proxy restrictions and fixed controller wiring. Positive HTTP handler wiring explicitly substitutes the live guard; existing authentication tests and anonymous-denial tests are separate. Native doubles are contract fixtures, not a live MongoDB replica-set or Clerk/provider acceptance run.

## Checklist presentation

Manual preparation now uses separate rows with a bold topic, short description, concrete action list and a right-aligned native checkbox. Completed rows receive a subtle theme-aware highlight. Mobile retains the right-hand control; long actions wrap. Existing saved step IDs, keyboard-accessible completion labels and the distinction between manual completion and server verification are preserved. Older guides without structured actions keep their instruction text as a fallback.
