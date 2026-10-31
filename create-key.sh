#!/bin/sh
# Generate three independent 256-bit tenant keys as .env assignments.
# Prints only; does not save or replace any configuration.
set -eu

if [ "$#" -ne 1 ]; then
  printf 'Usage: %s PREFIX (example: workflow-local:fcrww or WORKFLOW_REAL_FCRWW)\n' "$0" >&2
  exit 2
fi

exec node -e '
const argument = process.argv[1];
const reference = /^workflow-local:([a-z0-9]+(?:-[a-z0-9]+)*)$/.exec(argument);
const prefix = reference
  ? `WORKFLOW_REAL_${reference[1].toUpperCase().replace(/-/g, "_")}`
  : argument;
if (!/^[A-Z][A-Z0-9_]*$/.test(prefix) || /^(NEXT_PUBLIC_|PUBLIC_|VITE_)/.test(prefix)) {
  process.stderr.write("Use workflow-local:<tenant-name> or an uppercase server-only prefix (example: WORKFLOW_REAL_FCRWW).\n");
  process.exit(2);
}
const { randomBytes } = require("node:crypto");
for (const suffix of ["WRAPPING_KEY_V1", "INDEX_KEY", "CONTROL_KEY"]) {
  process.stdout.write(`${prefix}_${suffix}=${randomBytes(32).toString("base64")}\n`);
}
' -- "$1"
