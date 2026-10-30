# Tenant Explorer Implementation Plan

> Execute inline using superpowers:executing-plans. User authorized autonomous design and implementation.

**Goal:** Bootstrap the React explorer and NestJS explorer API for platform administration of all tenants.

**Architecture:** Separate Next.js App Router UI and NestJS API. Clerk platform identity plus explicit server-side subject allowlist. MongoDB control-plane transactions preserve tenant definitions, host bindings, runtime user grants, and monotonic revisions. Explorer-owned configuration and encrypted integration credentials have explicit namespaces; they do not silently overwrite the runtime's encrypted operational records.

**Tech Stack:** Node 24, npm, TypeScript, React 19, Next.js 16, Tailwind 4, NestJS 12, MongoDB 7, Clerk.

## Constraints and design decisions

- Use the two supplied empty repositories in place. Preserve .idea and all existing files; no commit, push, service startup or live database changes.
- API port 3003; UI port 3002. Existing app/API remain on their existing ports.
- Authenticated browser uses same-origin Next.js proxy; upstream sees a verified Clerk session token, never a shared browser API key.
- All write endpoints require optimistic revision; domain uniqueness scoped by environment. Create provisioning tenants; disabling preserves audit/history.
- Tenant users are existing Clerk subjects and tenant permission grants; no creation/deletion of external Clerk accounts.
- Credentials use AES-256-GCM, contextual AAD and a separately configured 32-byte server key. No HTTP secret retrieval. Do not call providers or provision DNS/databases automatically.
- Explorer integration configuration/credentials are administrative control records. Runtime operational encryption and provider activation require an explicit adapter, documented rather than pretending this occurs automatically.

## Review Focus

Cross-environment host collisions; stale concurrent saves; missing/foreign platform credentials; secret disclosure in API responses/audit/errors; list selection and unsaved edits during asynchronous UI operations.

## Task 1: Transactional tenant administration API

Files: src/contracts.ts, src/repository.ts, src/tenant.service.ts, src/vault.ts, test/tenant.test.ts, test/memory-repository.ts.

- [x] Write tests for create/list/update, domain collisions, stale revision, lifecycle and runtime authority coherence, user grant revocation, encrypted credential replacement/revocation, sanitized audit.
- [x] Run npm test and observe missing implementation failures.
- [x] Implement strict schemas, Mongo transactional repository and service using expectedRevision. New tenant creates coherent definition/hosts/runtime authority; preserve unknown internal fields on edits. List is paginated.
- [x] Run npm test; all tests pass.

## Task 2: Authenticated HTTP surface

Files: src/auth.ts, src/tenant.controller.ts, src/app.ts, src/main.ts, test/http.test.ts, .env.example, README.md.

- [x] Write HTTP tests for denied anonymous/non-admin access, strict body validation, tenant isolation and safe errors.
- [x] Implement Clerk signature/issuer/authorized-party verification with explicit admin subject allowlist, request limits, security headers, safe errors, Swagger bearer metadata and health endpoint.
- [x] Run npm test and npm run build.

## Task 3: Explorer user interface

Files: src/app/_, src/components/_, src/lib/_, src/proxy.ts, test/_, .env.example, README.md.

- [x] Test API error/abort handling and tenant list/editor interactions using real components with test transport.
- [x] Build responsive searchable tenant directory, create dialog, tenant overview/domain/configuration/integrations/credential/user/audit tabs. Show loading/empty/error states, dirty guards, conflict messages and pending actions.
- [x] Add Clerk sign-in/admin access and fixed-upstream same-origin proxy. No secret values stored locally.
- [x] Run npm test, npm run typecheck, npm run lint and npm run build. Browser QA only if user already runs explorer; never start services.

## Execution ledger

Ruling: Work in the explicitly supplied repositories rather than creating other worktrees; they have no source/history and were selected by the user.
Ruling: No automatic provider provisioning or live data migration; bootstrapping and code changes are authorized, real infrastructure mutations were not requested.

## Verification record

- API: 15 domain/native-adapter/HTTP tests pass; actual signed JWT verification included.
- Frontend: 11 client/proxy/React tests pass; typecheck and ESLint pass.
- API and frontend production builds are verified separately from the existing watch output.
- Independent review found two P2 issues (retained grant issuer migration and discarded form values); regression tests reproduced both, fixes passed, reviewer verified both fixes.
- Existing browser preview at port 3002 renders the setup screen. Authenticated visual/live MongoDB QA remains dependent on Clerk and database configuration. No server start/restart or real data mutation occurred.
- Ruling: Preserve historical grants and reject identity realm migration while any remain; a dedicated migration is required to maintain the runtime issuer invariant.
- Ruling: Reset the editor when accepting discard to open creation; protect tenant selection during pending saves.
