import { z } from 'zod';
import {
  environmentSchema,
  identifier,
  parse,
  type Aggregate,
} from '../contracts.js';
import type { InvitationState } from '../invitations/types.js';
export const checklist = [
  {
    id: 'ownership',
    label:
      'Verify exclusive ownership and all database locations against the server inventory.',
  },
  {
    id: 'access',
    label:
      'Revoke external memberships, service access, API keys and pending invitations.',
  },
  {
    id: 'work',
    label:
      'Stop schedules and reconcile in-flight jobs, emails and unknown external outcomes.',
  },
  {
    id: 'files',
    label:
      'Remove tenant-owned external files and backups under the approved retention policy.',
  },
  {
    id: 'providers',
    label:
      'Disconnect Bexio, Matrix, SMTP, IMAP, Dropbox and Pingen; protect shared accounts.',
  },
  {
    id: 'identity',
    label:
      'Remove exclusively owned Clerk resources; preserve shared identities and realms.',
  },
  {
    id: 'domains',
    label:
      'Remove tenant-owned DNS records and certificates; verify domain release.',
  },
  {
    id: 'caches',
    label:
      'Clear tenant caches and running configuration copies on every runtime instance.',
  },
] as const;
export interface Scope {
  environment: string;
  tenantId: string;
}
export interface Operation extends Scope {
  actor?: string;
  id: string;
  phase: 'retained' | 'purging' | 'failed' | 'purged' | 'recovered';
  deletedAt: string;
  recoverUntil: string;
  revision: number;
  manifestRevision?: string;
  targets: { id: string; label: string; done: boolean }[];
  leaseId?: string;
  leaseUntil?: number;
  error?: string;
  completedAt?: string;
}
export interface DeletionState {
  tenant: Aggregate;
  operation?: Operation;
  invitations?: InvitationState;
  event?: { action: string; actor: string };
}
export interface DeletionTransaction {
  reserveTargets(operationId: string, manifestRevision: string): Promise<void>;
}
export interface DeletionStore {
  transact<T>(
    scope: Scope,
    work: (
      state: DeletionState,
      transaction: DeletionTransaction,
    ) => Promise<T>,
  ): Promise<T>;
  finish(scope: Scope, operationId: string, leaseId: string): Promise<void>;
}
export interface Inventory {
  revision: string;
  complete: boolean;
  controlOnly?: boolean;
  targets: { id: string; label: string }[];
  reason?: string;
}
export interface PurgePort {
  inventory(scope: Scope): Promise<Inventory>;
  erase(scope: Scope, targetId: string): Promise<void>;
  absent(scope: Scope, targetId: string): Promise<boolean>;
}
export const confirmSchema = z.strictObject({
  expectedRevision: z.number().int().positive(),
  confirmation: z.string().max(140),
});
export const removeSchema = confirmSchema.extend({
  expectedAuthorityRevision: z.number().int().nonnegative(),
  expectedInvitationRevision: z.number().int().nonnegative(),
});
export const operationSchema = confirmSchema.extend({
  operationId: z.string().uuid(),
  expectedOperationRevision: z.number().int().positive(),
});
export const purgeSchema = operationSchema.extend({
  completed: z
    .array(
      z.enum(
        checklist.map((x) => x.id) as [
          (typeof checklist)[number]['id'],
          ...(typeof checklist)[number]['id'][],
        ],
      ),
    )
    .max(checklist.length),
  allDone: z.literal(true),
  ownershipConfirmed: z.literal(true),
  unregisteredResourcesConfirmed: z.literal(true),
  controlOnly: z.boolean(),
  expectedInventoryRevision: z.string().min(1).max(128),
});
export function scopeKey(s: Scope) {
  parse(environmentSchema, s.environment);
  parse(identifier, s.tenantId);
  return `${s.environment}/${s.tenantId}`;
}
/** Add calendar months in Europe/Zurich, preserving wall time and clamping month end. */
export function recoveryDeadline(iso: string): string {
  const date = new Date(iso);
  const formatter = new Intl.DateTimeFormat('en-GB', {
    timeZone: 'Europe/Zurich',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
  });
  const parts = (d: Date) =>
    Object.fromEntries(
      formatter
        .formatToParts(d)
        .filter((p) => p.type !== 'literal')
        .map((p) => [p.type, Number(p.value)]),
    ) as Record<string, number>;
  const p = parts(date),
    month = p.month! + 2,
    year = p.year! + Math.floor(month / 12),
    m = month % 12,
    day = Math.min(p.day!, new Date(Date.UTC(year, m + 1, 0)).getUTCDate());
  const wall = Date.UTC(
    year,
    m,
    day,
    p.hour!,
    p.minute!,
    p.second!,
    date.getUTCMilliseconds(),
  );
  let guess = wall;
  for (let i = 0; i < 4; i++) {
    const q = parts(new Date(guess));
    const currentWall = Date.UTC(
      q.year!,
      q.month! - 1,
      q.day!,
      q.hour!,
      q.minute!,
      q.second!,
      date.getUTCMilliseconds(),
    );
    const next = guess + wall - currentWall;
    if (next === guess) break;
    guess = next;
  }
  return new Date(guess).toISOString();
}
