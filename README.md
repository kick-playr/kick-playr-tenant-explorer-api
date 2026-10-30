# Kick Playr Tenant Explorer API

Separate NestJS platform administration API for the sibling `kick-playr-tenant-explorer` Next.js application. Uses Node 24, npm, TypeScript, NestJS 12, MongoDB and Clerk, matching the existing API's stack.

## Setup

1. Run `npm install` and copy `.env.example` to `.env`.
2. Configure the **platform operator** Clerk issuer and secret key (or PEM JWT verification key). Set `EXPLORER_ADMIN_SUBJECTS` to the comma-separated Clerk user IDs allowed to administer the platform. Configure `EXPLORER_AUTHORIZED_PARTIES` with the exact explorer origins. The frontend uses the same Clerk instance and allowlist.
3. Use the existing **`app-local-control-kick-playr-ch`** database. This is set in `.env.example` and the local explorer configuration. Set `EXPLORER_MONGODB_URI` to the existing cluster connection; `EXPLORER_CONTROL_DATABASE=app-local-control-kick-playr-ch` explicitly selects the database even if the URI names a different default database. Preserve the connection's authentication settings. Use a MongoDB replica set or Atlas; never select an operational club database.
4. Generate a separate 32-byte random credential key and configure `EXPLORER_CREDENTIAL_KEY` as 64 hexadecimal characters. Keep it stable and backed up in secret storage. The explorer does not read or copy secrets from the sibling API's environment.
5. When you want to start it, run `npm run dev` (watch mode, port **3003**). `npm run build && npm start` runs the compiled API. The default host is loopback; configure `HOST` explicitly for hosting.

On startup the repository connects and ensures unique indexes on the tenant, host, authority and explorer metadata collections. Existing duplicate data prevents startup rather than silently changing ownership. No data is seeded or migrated automatically. Use a dedicated database identity restricted to the control database and its required collections.

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

Public `/healthcheck` is liveness only. `/docs` contains Swagger UI with bearer authentication metadata and body examples. No persistent Swagger authorization or public readiness checks are enabled. The API sends no CORS grants: browser access goes through the same-origin frontend proxy. Body limit is 64KB; rate limit is 120 requests per minute per source IP. Behind a reverse proxy, configure trust and rate-limit infrastructure deliberately rather than trusting arbitrary forwarded headers.

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

The existing runtime currently binds operational resources through explicit development manifests and restricts supported tenants/environments. Creating a new tenant record, changing its references, or activating a tenant **does not provision or wire** its Mongo database, identity keys, encryption keys, provider accounts, DNS, TLS or deployment. Configure the consuming runtime separately; an active control record alone does not make an unbound tenant usable.

`tenantExplorerConfiguration` holds explorer-owned non-secret administrative JSON, provider connection records and the credential vault. These records are **not** the existing tenant runtime's encrypted `settings`, `tokens` or `integration_connections`. This bootstrap deliberately does not overwrite or attempt to decrypt those operational records. A future explicit adapter must translate/activate administrative connections through the existing tenant-scoped runtime integration services. The UI states this boundary. No Bexio, Matrix, SMTP, IMAP, Dropbox or Pingen provider is called by this API.

Tenant users mean existing Clerk `issuer`/`subject` identities mapped to a positive Bexio `contactId` and an explicit list of `club:*` permissions. No external Clerk accounts are created/deleted, and platform permissions cannot be assigned through tenant grants. Changing the identity realm while any grants (including revoked grants) remain requires a separate explicit migration, because the runtime requires all grant issuers to match the realm.

Credentials are AES-256-GCM encrypted with fresh nonces and environment/tenant/credential-bound authenticated data. There is no HTTP plaintext retrieval endpoint. Responses, audit events and expected errors omit values and envelopes. Disable any linked enabled connection before replacing/revoking a secret. Revocation removes the current envelope; historical backups remain subject to the database's retention policy. Key rotation requires a controlled re-encryption migration; replacing the vault key alone makes old credentials unreadable. The vault belongs to the explorer and is not automatically a runtime secret resolver.

## Operational encryption key sources

The migrated local setup uses the six server-only variables `FCRWW_WRAPPING_KEY_V1`, `FCRWW_INDEX_KEY`, `FCRWW_CONTROL_KEY` and their `FCUSTER_` equivalents. Values are canonical base64 encodings of the original 32 bytes, stored in this API's ignored `.env` and the operational API's ignored `.env`. The original key files are retained unchanged as recovery copies; migrated bindings use the variables.

`EXPLORER_KEY_BINDINGS_JSON` holds non-secret binding metadata. It takes precedence over `EXPLORER_KEY_BINDINGS_FILE`, so Vercel does not need a local metadata file. Its format is:

```json
{
  "version": 1,
  "bindings": [
    {
      "tenantId": "fcrww",
      "environment": "development",
      "controlDatabase": "app-local-control-kick-playr-ch",
      "keyReference": "real-development:fcrww:key",
      "version": "v1",
      "profile": "real-development",
      "variables": {
        "wrapping": "FCRWW_WRAPPING_KEY_V1",
        "index": "FCRWW_INDEX_KEY",
        "control": "FCRWW_CONTROL_KEY"
      }
    }
  ]
}
```

The **Keys** tab calls authenticated `GET /api/platform/tenants/:environment/:id/keys`. Bindings must match the control database, environment, tenant and current key reference exactly. The API returns only source type, variable name, version, status, size and fingerprint. Key values are never returned. Missing or invalid values fail closed; an environment binding never silently falls back to files. Temporary decoded key buffers are wiped after fingerprinting. This inspects configured key availability, rather than proving decryption against operational ciphertext.

Legacy `files: { wrapping, index, control }` bindings remain supported for unmigrated profiles. They require private owner-only regular 32-byte files and reject leaf symlinks and hard links. The local `.local/key-bindings.json` now contains variable names only, not secret material.

The original `real-development` references belong to `app-local-control-kick-playr-ch`; do not substitute the distinct newer workflow-real keys. The six existing keys were also stored as Vercel Secrets in `api-kick-playr-ch` **Preview only**. Production was untouched, and no deployment was triggered. The operational API repository documents its explicit `env:VARIABLE_NAME` references and upload helper in `docs/tenancy/tenant-key-environment.md`.

## Verification

`npm test` compiles and runs domain, native-adapter and HTTP tests. Authentication tests use actual signed RSA JWTs and Clerk verification. Domain tests use a transactional in-memory storage double; adapter tests use a native driver double. HTTP tests initialize Nest in-process and close it after each case. No development server, real database or provider connection is needed.

`npm run typecheck` and `npm run build` verify TypeScript. Live MongoDB transactions, real provider activation and a real Clerk browser session require the configured services; offline tests do not establish those deployment properties.
