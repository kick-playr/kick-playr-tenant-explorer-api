# Club Administration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Implement natively; retain existing working tree edits and do not commit or publish.

**Goal:** Let active club administrators use the explorer to manage their own operational settings and integrations without creating a second secret store.

**Architecture:** Keep platform routes guarded by the operator allowlist. Add a session-authenticated club API whose discovery and every operation require an exact active issuer/subject grant in a current active tenant authority. Forward only fixed settings and integration operations to a server-configured club runtime proxy, preserving the user's bearer token; the runtime repeats live authorization and stores changes in its existing encrypted club collections.

**Tech Stack:** Existing NestJS, Next.js/React, Clerk, MongoDB and tenant runtime cryptography.

**Spec:** User-approved permission split in this conversation: infrastructure and encryption keys are platform-only; clubs administer their own settings and live integration connections.

## Global Constraints

- No new development services or restarts; existing watchers may reload changes.
- Never return stored credential values, accept browser-supplied upstream destinations, or write club credentials into explorer metadata.
- Existing platform editor and uncommitted layout changes remain intact.
- No automatic grants, arbitrary issuer discovery, provider-secret migration, commits, pushes, or deployments.
- Explorer sign-in must use the club grant's Clerk issuer; additional realms require explicit dedicated-host bindings and pinned API verification keys.

## Review Focus

- Revoked grants, disabled authorities, issuer collisions and changed tenant revisions deny access before transport.
- A club cannot enumerate foreign tenants or call platform routes with a forged URL.
- Runtime origins and route suffixes are allowlisted, redirect-free and bounded.
- Credential writes use current revisions and stay in runtime encrypted repositories; API errors never echo values.
- A failed save retains non-secret edits, clears secret inputs and never implies a successful update.

### Task 1: Club authentication and authorization

Files: explorer-api `src/auth.ts`, `src/repository.ts`, `src/club-access.ts`, `src/club.controller.ts`, `src/app.ts`, HTTP tests.

- [x] Add failing signed-JWT tests for own-club discovery, foreign-club denial, revoked/mismatched grants and platform isolation.
- [x] Extract session verification, retain the platform allowlist, and add exact grant-based club discovery/rechecks.
- [x] Return only club identity/display metadata; no infrastructure references or authority user lists.

### Task 2: Runtime bridge

Files: explorer-api `src/club-runtime.ts`, `src/main.ts`; runtime existing settings/integration services and route allowlist as needed.

- [x] Test fixed configured upstreams, allowed methods, bounded safe responses, revocation before dispatch and sanitized failures.
- [x] Forward the user's token to the configured tenant proxy. Preserve runtime optimistic concurrency and encrypted custody.
- [x] Provide live settings, integration metadata, OAuth reconnection and write-only credential administration supported by runtime repositories.

### Task 3: Club explorer

Files: frontend `src/app/page.tsx`, `src/app/api/explorer/[...path]/route.ts`, `src/lib/proxy.ts`, `src/components/club-explorer.tsx`, UI tests.

- [x] Test restricted tenant selection, real runtime settings saves and secret input clearing.
- [x] Fetch access from the API rather than rejecting every non-operator in Next.js.
- [x] Render a separate club workspace with operational settings and integrations, retaining the platform workspace for operators.

### Task 4: Configure, verify and document

- [x] Configure only non-secret local runtime routing and explicitly trusted explorer origins where the existing runtime supports them.
- [x] Run both explorer suites, builds, lint and targeted runtime tests/typechecks.
- [x] Document required grants, Clerk issuer/origin setup, encrypted storage ownership and platform-only controls.
- [x] Obtain one independent final review; resolve security findings before reporting completion.


## Execution rulings and verification

- The live club uses a different Clerk issuer from the platform console. Added an explicit `fcrww.explorer.localhost:3002` sign-in host, pinned API verification key, and encrypted Clerk middleware key propagation rather than widening platform authorization. Subject collisions across realms are tested and denied platform access. Private Clerk server keys remain in ignored dotenv; provider credentials and tenant grants were not moved or widened.
- Live network checks found that Node Fetch replaced the configured virtual Host with the loopback connection address. Native HTTP/HTTPS transport now preserves the fixed Host. A real HTTP fixture reproduced the bug before the fix; a live anonymous probe now reaches the club proxy and is rejected with 401.
- Existing club application proxy contracts gained the three operational integration routes. Runtime credentials are changed through the real encrypted repositories, not the explorer metadata store.
- Verification: 26 explorer API tests, 22 frontend tests, 82 runtime targeted tests, both explorer builds, frontend lint, runtime typecheck, proxy contract smoke check, dedicated-host sign-in rendering and private-key non-exposure checks.
- Independent review found no actionable P1/P2 findings in authorization, realm selection and credential storage. Native transport received an additional final review.
- User explicitly authorized starting the existing tenant stack; it is running on 4311/4312 with the scheduler still manual. No provider writes or account-grant changes were exercised live. Full authenticated browser sign-in requires the user's club session; real cryptography/tenant isolation and JWT audience/origin/revocation were verified with synthetic test credentials.
