# Hide deleted tenants from normal lists

User approved this list-only correction; Chris approved the exact predicate and fixture semantics.

- Add failing native repository fixtures proving normal/search/status/environment lists and counts exclude documents with any deletionId property, including retained/purged and falsy legacy markers. Deleted-only lists include those markers; recovered records with the property removed remain visible. Verify pagination is applied after filtering and find/count share the predicate.
- Match the in-memory repository using property presence, not truthiness.
- Apply only filter.deletionId = { $exists: query.deletion === 'only' } in the native list adapter.
- Add a failing UI test for the explicit Deleted tenants filter request, returned rows, count and pagination reset. Rename that option only; retain deletion=only query behavior.
- Refresh directory queries/counts and return to page 1 when tenant detail reload follows delete/recovery/purge, retaining selected details. Exercise real deletion and recovery components against fixture transport.
- Run full API/UI tests, both typechecks, UI lint and diff checks. No lifecycle, authorization, purge, service or live database changes. No commit/version bump; coordinator handles delivery.

Verification: Chris approved list-only architecture; Trip independent repository+UI QA PASS, including integrated deletion/recovery refresh and10 Explorer tests. Parent fresh full API141/141 and UI101/101, typechecks/UI lint/diff checks pass. Version API0.1.7→0.1.8; UI0.1.6→0.1.7. APP release-date command01.11.2026 produced no diff. No real DB calls/services/deployments.
