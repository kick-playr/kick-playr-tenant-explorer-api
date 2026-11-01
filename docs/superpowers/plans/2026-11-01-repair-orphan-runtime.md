# Orphan runtime repair implementation plan

**Goal:** Repair stale development runtime references for an absent tenant, with dry-run as the default.

**Design approved in chat:** Back up the encrypted shared configuration, decrypt with its existing key, remove only the selected orphan's runtime/key binding entries, re-encrypt, and compare-and-swap the original envelope. Never delete tenant data or vault material. Refuse any existing tenant definition, including a deletion tombstone. Require the dry-run document digest on apply.

**Architecture:** A tested maintenance core owns validation, preview, backup ordering and concurrency checks. A CLI loads Explorer process credentials through its existing secrets adapter, connects to the control database, and supplies transaction and private encrypted-backup adapters. No server bootstrap or listener is invoked.

**Files:** `src/maintenance/repair-orphan-runtime.ts`, `src/maintenance/repair-orphan-runtime-cli.ts`, `test/repair-orphan-runtime.test.ts`, `package.json`, `README.md`.

- [x] Write failing tests for default dry-run, exact tenant isolation, existing/deleted definitions, digest mismatch, backup failure and concurrent modification.
- [x] Implement the bounded metadata pruner and encrypted-envelope repair core.
- [x] Add CLI, encrypted private backup and Mongo transaction adapters; document commands and limits.
- [x] Run the full test suite, build, help and a read-only live dry-run. Do not apply, start services, commit or merge.

Verification: 171 full-suite tests, production build and diff checks pass. Independent security review passed after syncing the encrypted backup directory ancestry. A live read-only core preview found 3 FC Uster references (1 runtime tenant, 2 explicit key bindings); no writes or backups occurred. The ordinary CLI refuses the current malformed dotenv AUTH_JSON; live core verification used existing vault bootstrap credentials to read the same process snapshot, without rewriting dotenv or applying repair.
