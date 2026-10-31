# Kick Playr Tenant Explorer API

Separate NestJS platform administration API for the sibling `kick-playr-tenant-explorer` Next.js application. Uses Node 24, npm, TypeScript, NestJS 12, MongoDB and Clerk, matching the existing API's stack.

## Setup

1. Run `npm install` and copy `.env.example` to `.env`.
2. Configure the **platform operator** Clerk secret key (or PEM JWT verification key) as bootstrap credentials. The platform issuer, administrator subject allowlist and exact authorized explorer origins are stored in the encrypted database configuration, alongside the club realm and routing policy.
3. Use the existing **`app-local-real-control-kick-playr-ch`** database. This is set in `.env.example` and the local explorer configuration. Set `EXPLORER_MONGODB_URI` to the existing cluster connection; `EXPLORER_CONTROL_DATABASE=app-local-real-control-kick-playr-ch` explicitly selects the database even if the URI names a different default database. Preserve the connection's authentication settings. Use a MongoDB replica set or Atlas; never select an operational club database.
4. Configure the existing `WORKFLOW_SHARED_WRAPPING_KEY_V1` as canonical base64 for exactly 32 bytes. It decrypts the shared configuration document; preserve it during migration. Separately configure the stable `EXPLORER_CREDENTIAL_KEY` as 64 hexadecimal characters for the Explorer credential vault. Back up both keys in secret storage. The explorer does not read or copy secrets from the sibling API's environment.
5. When you want to start it, run `npm run dev` (watch mode, port **3003**). `npm run build && npm start` runs the compiled API. The default host is loopback; configure `HOST` explicitly for hosting.

Before constructing application services, startup reads and validates the encrypted shared configuration; missing, invalid or unauthenticated configuration prevents startup. No environment JSON or configuration-file fallback is available. After configuration loads, the repository connects and ensures unique indexes on the tenant, host, authority and explorer metadata collections. Existing duplicate data prevents startup rather than silently changing ownership. No data is seeded or migrated automatically. Use a dedicated database identity restricted to the control database and its required collections.

## Routes

All management routes start with `/api/platform/tenants` and require `Authorization: Bearer <platform Clerk session token>`. The browser calls the frontend proxy, which obtains this token server-side. Ordinary club sessions and API keys cannot grant platform access. Every existing-tenant write includes the positive integer `expectedRevision` from its current `configRevision`. Conflicts return HTTP 409; reload and review before retrying.

| Method | Suffix                                         | Operation                                                                                                                        |
| ------ | ---------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| GET    | `/`                                            | Paginated search: `page`, `pageSize` (max 100), `search`, `environment`, `status`                                                |
| POST   | `/`                                            | Create tenant in `provisioning`                                                                                                  |
| GET    | `/:environment/:id`                            | Tenant details, grants and redacted credential metadata                                                                          |
| PATCH  | `/:environment/:id`                            | Public identity, lifecycle, canonical hostname, aliases, identity realm, opaque runtime references, administrative configuration |
| PUT    | `/:environment/:id/users/:subject`             | Create/update an existing Clerk user's tenant grant                                                                              |
| DELETE | `/:environment/:id/users/:subject`             | Revoke the grant and advance its generation                                                                                      |
| PUT    | `/:environment/:id/credentials/:credentialId`  | Write/replace an encrypted secret                                                                                                |
| DELETE | `/:environment/:id/credentials/:credentialId`  | Revoke the credential and remove its encrypted value                                                                             |
| PUT    | `/:environment/:id/integrations/:connectionId` | Create/update administrative provider configuration                                                                              |
| DELETE | `/:environment/:id/integrations/:connectionId` | Remove a disabled administrative connection                                                                                      |
| GET    | `/:environment/:id/audit`                      | Latest 100 administrative events                                                                                                 |

Public `GET /public/realm?host=<registered-host>` resolves only exact registered frontend hosts. A platform host returns `{host, club:false}`; a club host returns `{host, club:true, publishableKey, secretVariable}`. The last field is an environment-variable name, never its secret value. Unknown hosts return 404; malformed or ambiguous queries return 400. No settings, private keys, administrator lists or credentials are exposed. Public `/healthcheck` is liveness only. `/docs` contains Swagger UI with bearer authentication metadata and body examples. No persistent Swagger authorization or public readiness checks are enabled. The API sends no CORS grants: browser access goes through the same-origin frontend proxy. Body limit is 64KB; rate limit is 120 requests per minute per source IP. Behind a reverse proxy, configure trust and rate-limit infrastructure deliberately rather than trusting arbitrary forwarded headers.

Example creation body:

```json
{
  "id": "my-club",
  "environment": "development",
  "hostname": "my-club.localhost:4311",
  "aliases": [],
  "public": { "name": "My Club", "locale": "de-CH" },
  "secretReferences": {
    "mongoUri": "tenant:my-club:mongo",
    "key": "tenant:my-club:key"
  },
  "identityRealm": "https://club-instance.clerk.accounts.dev"
}
```

## Runtime compatibility and boundaries

The API reuses `tenantDefinitions`, `tenantHostBindings`, and `tenantRuntimeAuthorities` from `fcrww-api-kick-playr-ch/src/tenancy`. Definition and complete domain-set changes, runtime lifecycle/user grants, revision increments, explorer metadata and audit are committed in one primary snapshot/majority Mongo transaction. Both the definition revision and prior authority revision are checked. Runtime-owned internal fields and service grants are preserved. Every mutation increments `configRevision`, `authorityRevision` and `supportRevision`; user grant changes also advance their own revision. Provisioning maps to a disabled runtime authority. Tenants are disabled rather than physically deleted, retaining host reservations and history.

The existing runtime binds infrastructure and policy through encrypted shared control-database configuration and reads operational records from encrypted club databases. It still restricts supported tenants/environments. Creating a new tenant record, changing its references, or activating a tenant **does not provision or wire** its Mongo database, identity keys, encryption keys, provider accounts, DNS, TLS or deployment. Configure the consuming runtime separately; an active control record alone does not make an unbound tenant usable.

`tenantExplorerConfiguration` holds explorer-owned non-secret administrative JSON, provider connection records and the credential vault. These records are **not** the existing tenant runtime's encrypted `settings`, `tokens` or `integration_connections`. This bootstrap deliberately does not overwrite or attempt to decrypt those operational records. A future explicit adapter must translate/activate administrative connections through the existing tenant-scoped runtime integration services. The UI states this boundary. No Bexio, Matrix, SMTP, IMAP, Dropbox or Pingen provider is called by this API.

Tenant users mean existing Clerk `issuer`/`subject` identities mapped to a positive Bexio `contactId` and an explicit list of `club:*` permissions. No external Clerk accounts are created/deleted, and platform permissions cannot be assigned through tenant grants. Changing the identity realm while any grants (including revoked grants) remain requires a separate explicit migration, because the runtime requires all grant issuers to match the realm.

Credentials are AES-256-GCM encrypted with fresh nonces and environment/tenant/credential-bound authenticated data. There is no HTTP plaintext retrieval endpoint. Responses, audit events and expected errors omit values and envelopes. Disable any linked enabled connection before replacing/revoking a secret. Revocation removes the current envelope; historical backups remain subject to the database's retention policy. Key rotation requires a controlled re-encryption migration; replacing the vault key alone makes old credentials unreadable. The vault belongs to the explorer and is not automatically a runtime secret resolver.

## Database configuration

The shared control collection `tenantWorkflowConfiguration` contains the document
`_id: "runtime:development"`. Its version-1 AES-256-GCM envelope uses authenticated
data `["kick-playr:tenant-workflow-configuration", databaseName, 1]` and contains the
version-2 shared runtime payload. Explorer consumes only its `explorer` section:

- `issuer`, `authorizedParties`, `adminSubjects`: platform authorization policy.
- `keyBindings`: version-1 binding metadata containing existing environment-key references.
- `clubRuntimes`: fixed tenant application-proxy destinations.
- `clubRealms`: explicitly trusted issuers, origins and pinned RSA public keys.
- `frontendHosts`: exact host-to-publishable-key and secret-variable-name mappings.
- `platformHosts`: exact hosts permitted to use the frontend's platform Clerk bootstrap.

Keep MongoDB bootstrap connection details, the shared wrapping key, the separate
Explorer vault key, tenant encryption-key bytes and Clerk SDK server secrets in
server-only environment/secret storage. Runtime configuration is authoritative in
MongoDB; changing old environment JSON values has no effect. Update the shared
document through an explicit authenticated migration, preserving existing keys,
records and grants. Neither startup nor the public realm endpoint seeds data.

## Operational encryption key sources

The current local explorer selects the same `workflow-real` control database as the tenant-local API: `app-local-real-control-kick-playr-ch`. Its server-only key bindings use `WORKFLOW_REAL_FCRWW_WRAPPING_KEY_V1`, `WORKFLOW_REAL_FCRWW_INDEX_KEY`, `WORKFLOW_REAL_FCRWW_CONTROL_KEY` and the corresponding `WORKFLOW_REAL_FCUSTER_` variables. They contain the existing workflow-real key bytes; no keys were rotated. The historical unprefixed FCRWW/FCUSTER variables and original control database are preserved separately.

The configured real control database currently contains FCRWW only. FC Uster's copied settings live in its separate operational database; copying those settings did not create tenant authority or backend accounts. The explorer does not activate Uster automatically.

`explorer.keyBindings` in the encrypted shared configuration holds binding metadata with environment-variable names only. Its format is:

```json
{
  "version": 1,
  "bindings": [
    {
      "tenantId": "fcrww",
      "environment": "development",
      "controlDatabase": "app-local-real-control-kick-playr-ch",
      "keyReference": "workflow-local:fcrww:key",
      "version": "v1",
      "profile": "workflow-real",
      "variables": {
        "wrapping": "WORKFLOW_REAL_FCRWW_WRAPPING_KEY_V1",
        "index": "WORKFLOW_REAL_FCRWW_INDEX_KEY",
        "control": "WORKFLOW_REAL_FCRWW_CONTROL_KEY"
      }
    }
  ]
}
```

The **Keys** tab calls authenticated `GET /api/platform/tenants/:environment/:id/keys`. Bindings must match the control database, environment, tenant and current key reference exactly. The API returns only source type, variable name, version, status, size and fingerprint. Key values are never returned. Missing or invalid values fail closed; an environment binding never silently falls back to files. Temporary decoded key buffers are wiped after fingerprinting. This inspects configured key availability, rather than proving decryption against operational ciphertext.

Only environment-variable key bindings are accepted. Legacy file bindings and configuration-file loaders are rejected; no `.local` file is read by the running Explorer API.

The original `real-development` references belong to `app-local-control-kick-playr-ch`; do not substitute the distinct newer workflow-real keys. The six existing keys were also stored as Vercel Secrets in `api-kick-playr-ch` **Preview only**. Production was untouched, and no deployment was triggered. The operational API repository documents key custody and its upload helper in `docs/tenancy/tenant-key-environment.md`; runtime key-reference metadata is database-owned.

## Verification

`npm test` compiles and runs domain, native-adapter and HTTP tests. Authentication tests use actual signed RSA JWTs and Clerk verification. Domain tests use a transactional in-memory storage double; adapter tests use a native driver double. HTTP tests initialize Nest in-process and close it after each case. No development server, real database or provider connection is needed.

`npm run typecheck` and `npm run build` verify TypeScript. Live MongoDB transactions, real provider activation and a real Clerk browser session require the configured services; offline tests do not establish those deployment properties.

The runtime installer recognizes the explorer's two optional metadata collections and their exact indexes, without reading their contents or relaxing checks for unknown collections. Its existing authority/revision validation remains enforced: control-plane edits still need matching runtime bindings and an intentional configuration rollout. Changing the explorer database does not perform that rollout or copy credentials from the old explorer vault. Local dotenv changes take effect when the explorer API is restarted.

## Club administrator access

The explorer now has a separate club workspace. Platform operators retain the existing platform console; operators who also hold a club grant can open **My club settings**. Other signed-in users see only clubs for which they have an active administrator grant.

Club discovery requires an exact Clerk issuer + subject match in an active `tenantRuntimeAuthorities.users` grant, both `club:settings:read` and `club:settings:write`, and a matching active tenant definition/authority revision. Integrations additionally require the existing runtime integration permissions and a current, non-anonymized club administrator role. Revocations are checked again by the runtime. Club routes cannot create tenants or edit domains, lifecycle, user grants, database references, or encryption keys.

`explorer.clubRuntimes` in the encrypted shared configuration is a server-only list of fixed destinations:

```json
[
  {
    "tenantId": "my-club",
    "environment": "development",
    "hostname": "my-club.localhost:4311",
    "origin": "http://127.0.0.1:4311"
  }
]
```

The `hostname` must equal the current control-plane tenant hostname. The destination is the club's existing trusted application proxy, which signs the tenant assertion and forwards the user's original bearer token. It is not the bare API port. HTTP is limited to explicitly configured local development destinations; redirects and browser-supplied destinations are rejected.

Live operational settings are read/written through `/api/settings`, retaining the runtime `expectedHash` conflict check and encrypted club `settings` collection. Live integration metadata and replacements use `/api/settings/integrations`. SMTP/IMAP passwords and Pingen tokens/webhook secrets remain in the runtime's encrypted token repository. Disable a connection before replacement, then explicitly enable it again. Bexio and Dropbox reconnect through their existing OAuth flows; shared application credentials and routing remain operator-managed. The club workspace never writes these secrets into `tenantExplorerConfiguration`. Existing platform integration/credential tabs still represent separate administrative records.

Writes append value-free explorer audit intent/completion events. Runtime integration changes also append encrypted club audit events. Neither API returns stored credential values.

### Clerk setup

The platform console keeps its configured Clerk issuer. Clubs can use separate Clerk instances through explicit server-owned realm bindings. `explorer.clubRealms` contains a list of `{issuer, authorizedParties, jwtKey}` entries with pinned RSA public keys. Unknown issuers are rejected; a club subject matching a platform operator ID does not grant platform rights. Club grants must match the exact signed issuer and subject.

The encrypted `explorer.frontendHosts` map binds dedicated explorer hosts to the matching Clerk public key and a server-only secret-variable reference. `explorer.platformHosts` registers platform hosts explicitly. The frontend obtains only the public host projection through `/public/realm` and resolves the selected secret from its own server environment. Local club access is configured at `http://fcrww.explorer.localhost:3002`; the default `localhost:3002` platform console keeps its own sign-in. Clerk private keys stay in ignored server dotenv variables; only public verification keys are needed in the API realm registry. No Bexio credentials or tenant grants are moved or widened.

The runtime must explicitly trust the explorer origin and still requires its tenant-specific JWT audience. The shared runtime configuration supports `explorerOrigins: ["http://localhost:3002"]`; existing tenant origin validation remains separate. A default Clerk session token works only when its configured claims already contain the required runtime audience. Otherwise add the required `aud` to the club's normal session token in Clerk Dashboard → Sessions → Customize session token. For local FCRWW use `aud: kick-playr:development:fcrww`, preserving existing claims. Custom JWT templates cannot carry the session ID and are not supported by this session-bound authentication flow. Missing runtime authorization fails closed. No account grants are automatically created or widened.

### Administrator presets and wildcard permissions

In **Users → Add user / Edit user**, **Tenant administrator** adds the club settings, integration, OAuth and prerequisite read permissions. Unchecking it removes that preset while retaining other explicitly assigned permissions. Existing runtime/Bexio administrator checks still apply.

The exact shorthand `club:*:*` expands at save time into the current concrete club-permission catalog in `src/tenant-permissions.ts`. It never grants platform permissions or access to other tenants, and no wildcard is stored in runtime authority records. Future permissions are not automatically granted; update the catalog and save the grant again when intentionally widening access. Other wildcard patterns are rejected.

User writes send `expectedRevision` (runtime configuration) and `expectedAuthorityRevision` (access generation). Adding, replacing or revoking a grant advances authority/grant/support generations without changing the runtime configuration revision or encrypted-data bindings. Legacy callers that omit the authority revision are accepted only while the two revision values still match; stale or ambiguous edits fail closed and must be reloaded.

### Register tenant keys before runtime creation

During platform onboarding, install the three independently generated tenant keys
under the displayed `WORKFLOW_REAL_<TENANT>_WRAPPING_KEY_V1`, `_INDEX_KEY` and
`_CONTROL_KEY` names in both APIs' server environments. Choose **Schlüssel
konfigurieren** before the first manager invitation. This checks fresh,
short-lived HMAC attestations from both APIs and stores only the variable mapping
in the encrypted runtime document's `explorer.keyBindings.bindings`. Key values
and proofs are never returned to the browser or stored in the mapping. Existing
keys and mappings are retained; this action is not key rotation.

The development key check uses an existing database-pinned setup runtime origin
when the new tenant has no individual runtime binding. Only this platform-only
inspection action has that fallback. Operational/setup actions still require
their exact tenant binding and complete runtime configuration. Key-status reads
refresh mappings from the encrypted database immediately, without restarting the
API. A saved mapping clears provisioning verification; complete runtime metadata,
MongoDB, Clerk, provider setup and subsequent verification remain required before
inviting the first manager. Preview/production HSM custody is still unavailable.
