# Controlled tenant deletion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement task-by-task.

**Goal:** Add access-blocking deletion, three-calendar-month recovery and explicitly confirmed verified database purge.
**Architecture:** Durable separate tenant deletion operation, atomic lifecycle/access fencing, operator-owned target manifest and idempotent verified purge steps. Existing platform guards and accessible UI dialog remain authoritative.
**Tech Stack:** TypeScript, NestJS, MongoDB, Zod, Next.js/React, node:test.
**Spec:** ../specs/2026-11-01-app-29-delete-tenant.md

## Global Constraints
- Chris approved on 2026-11-01 with mandatory boundaries recorded in APP-29; implementation and isolated fixture tests only.
- No real destructive calls, services, migrations, deployment or main merge; feature PRs target development.
- Final checkbox + typed environment/tenantId + manual checklist mandatory anytime; no silent automatic expiry purge.
- Exact tenant/environment scope, exclusive server target manifest, no browser database location inputs; incomplete inventory blocks purge.
- Keep minimal tombstone/audit; recovery only before calendar deadline and purge latch, to disabled with fresh grants.

## Review Focus
- Interrupted purge must retry a deleted-but-unrecorded target and verify absence.
- Shared or re-assigned target must never be dropped; complete server ownership evidence required.
- Soft deletion must revoke all setup/invitation/runtime entry paths and generic edits cannot reactivate it.
- Active delivery lease or external uncertainty must block irreversible cleanup until reconciled.
- Checklist/revision/network-conflict UI must never imply deletion succeeded without operation state.

### Task 1: Backend lifecycle and purge
**Files:** new src/deletion/* (contracts/service/repository/purger/controller); modify app.ts/main.ts/tenant.service.ts and invitation/onboarding boundaries as required; fixture tests under test/deletion*.test.ts.
**Interfaces:** platform tenants /:environment/:id/deletion GET status, POST soft delete, POST recovery, POST purge; requests contain expected revision(s), exact confirmation, checklist IDs/final acknowledgment, never database locations. Freeze concrete request/response TypeScript interface in deletion/contracts.ts before UI task.
- [x] Write failing fixture tests for calendar arithmetic, lifecycle revocations/read-only fencing, recovery cutoff, cross-tenant isolation.
- [x] Run targeted tests and observe expected failures.
- [x] Implement atomic state/access changes using Mongo transaction and definition/invitation fences, audit, stable operation ID. Guard existing generic mutation/setup/invitation paths.
- [x] Write failing purge fixture tests: incomplete/shared/reserved manifest, active lease, stale revisions, duplicate/concurrent claim, crash after deletion, verify failure, scoped control/config cleanup.
- [x] Implement validated operator manifest, durable latch/lease, per-target progress/absence verification, encrypted envelope CAS cleanup and minimal tombstone/audit. Unknown inventory refuses purge. Never infer ownership from runtime name.
- [x] Run backend suite/typecheck. Record exact output and limitations.

### Task 2: Platform UX
**Files:** new src/components/tenant-deletion.tsx and shared deletion types; modify tenant-editor.tsx and directory display/read-only handling as required; tests test/deletion.test.tsx.
**Interfaces:** consume Task 1 routes/contracts verbatim; keep deleted detail resolvable through tombstone/status handling.
- [x] Write failing component tests for danger action, exact identity, complete manual checklist/final checkbox, recovery window, stale impact, retry/status/error.
- [x] Implement accessible existing Dialog integration, busy/dirty handling, server-rehydrated read-only status and failure retry under same operation. Separate lifecycle options from deletion states.
- [x] Run frontend tests/typecheck/lint; fix regressions.

### Task 3: Independent QA and delivery
- [x] Trip independently tests/reviews complete source diff, isolation, checklist flow and all required fixture failure classes. Resolve findings and rerun affected checks.
- [x] Update README/operator manifest setup and manual checklist, truthful scope/limitations. Record worktree/base/recovery identifiers and explicit review stages in Jira.
- [x] One patch bump per affected repository; run required APP release date command before staging release changes and preserve separate APP commit if needed. Do not duplicate bump retries.
- [ ] Commit/push feature branches only, create separate PRs to development, assign lolo8304 and attach each. No auto-merge/deploy.

## Verification evidence
Chris explicitly approved architecture/security before implementation (APP-29 comment 10085). Trip independently passed after a reproduced target reassignment race was fixed using durable reservations shared by assignment and purge transactions. Full API suite 130/130; UI suite 97/97; both typechecks, UI lint and diff checks passed. All tests used fixtures, no real destructive calls/services. Explorer patch 0.1.4→0.1.5; API 0.1.5→0.1.6. Companion APP release date generated using npm run release:date: 01.11.2026. No APP version bump solely for date refresh.
