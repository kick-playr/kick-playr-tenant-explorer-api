# UI-driven permanent deletion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans.

**Goal:** Remove the separate JSON inventory prerequisite using server-derived registered targets and explicit UI ownership confirmation.
**Architecture:** A shared async inventory resolver derives from authenticated runtime envelopes before claim and reads a scope/op/revision-bound encrypted snapshot after claim. Claim transaction freezes snapshot and reserves databases; finalization clears credentials after safe retry completion.
**Tech Stack:** Existing TypeScript/Nest/Mongo/Zod/React/node:test.
**Spec:** ../specs/2026-11-01-app-29-ui-deletion.md

## Global Constraints
No real database deletion, migrations, services, restart, deployment or auto-merge. Isolated feature branches codex/app-29-ui-delete-confirmation from current development. Only development has authoritative registry coverage. Browser never provides database location. Existing checklist/allDone/typed scope and backend platform admin remain mandatory.

## Review Focus
- Failed/retried purge after runtime prune must retain immutable target identity.
- Missing or malformed shared inventory must never mean empty safe inventory.
- Cross-tenant or protected database ownership overrides UI confirmation.
- Empty target list needs explicit control-only scope acknowledgment.
- Ciphertext must be bound to exact tenant/operation/revision and removed only after successful finalization.

### Task 1: Backend
Files src/deletion/{contracts,service,mongo}.ts, new focused inventory module, src/main.ts, tests deletion*.test.ts, README/.env.example.
- [x] Add failing fixture tests for manifest-free registered derivation, malformed/ambiguous/shared/protected bindings, unsupported scope, explicit no-binding acknowledgement, stale preview, scope substitution, retry after prune, final snapshot removal and reservation race.
- [x] Implement shared inventory resolution with transaction snapshot recomputation, scoped encrypted frozen record and current ownership rechecks. Remove startup environment manifest requirement without exposing credentials or weakening old operation failures.
- [x] Run full API tests and typecheck; all new/regression fixtures pass.

### Task 2: UI
Files src/components/tenant-deletion.tsx, src/lib/tenant-deletion.ts, test/deletion.test.tsx, README.
- [x] Add failing component tests for discovered DB preview, required ownership/manual cleanup confirmation, explicit control-only path, unsupported/error warning styling and stale preview reset.
- [x] Implement exact new API fields and explicit deletion scope wording with no env-setting requirement.
- [x] Run full UI tests/typecheck/lint.

### Task 3: Review/delivery
- [x] Trip independent fixture/code QA; resolve actionable issues.
- [x] One patch bump each affected repo, required APP release date command (date-only refresh requires no duplicate APP version bump); separate feature PRs against development assigned Lolo and attached. No auto-merge without fresh user request.

## Verification
Chris explicitly approved revised architecture before implementation. Trip independent QA PASS: 60 API fixture tests, 8 UI fixture tests, both typechecks and UI lint. Parent fresh complete suites: API139/139, UI99/99; typechecks/lint/diff checks pass. No real database calls or services. API version0.1.6→0.1.7, Explorer0.1.5→0.1.6. Required APP release-date command yielded01.11.2026 with no diff, so no companion date-only PR. Feature PRs target development, no automatic merge.
