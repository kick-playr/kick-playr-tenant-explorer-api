import type { ClientSession, MongoClient } from 'mongodb';
import type { Scope } from './index.cjs';
export interface RotationKey {
  name: string;
  version: string;
}
export type RotationKeys = Record<
  'wrapping' | 'index' | 'control',
  RotationKey
>;
export interface RotationPlan {
  scope: Scope;
  expectedRevision: number;
  dataset?:{database:string;cluster:string};
  fromDigest: string;
  toDigest: string;
  from: RotationKeys;
  to: RotationKeys;
  wrappingHistory?: { keyVersion: string; name: string; version: string }[];
}
export interface RotationStatus {
  operationId: string;
  scope: Scope;
  stage: string;
  fromDigest: string;
  toDigest: string;
  to: RotationKeys;
  wrappingKeyVersion: string;
  wrappingHistory: { keyVersion: string; name: string; version: string }[];
  waitUntil?: number;
  completed: number;
  total?: number;
  activatedRevision?: number;
}
export interface RotationLease {
  id: string;
  owner: string;
  epoch: number;
}
export interface RotationJob {
  id: string;
  plan: RotationPlan;
  owner: string;
  epoch: number;
  stage: string;
  unit: number;
  checkpoint: string | null;
  completed: number;
  inventoryDigest?: string;
  waitUntil?: number;
  total?: number;
  activatedRevision?: number;
}
export interface RotationContext {
  signal: AbortSignal;
  assertLease(): Promise<void>;
  lease: Readonly<RotationLease>;
  withWriteFence<T>(work: (session: ClientSession) => Promise<T>): Promise<T>;
}
export interface RotationWorker {
  inventory(
    plan: RotationPlan,
    context: RotationContext,
  ): Promise<{
    units: string[];
    roles: ('wrapping' | 'index' | 'control')[];
    total?: number;
  }>;
  migrateBatch(
    plan: RotationPlan,
    context: RotationContext & {
      unit: string;
      checkpoint: string | null;
      limit: number;
    },
  ): Promise<{
    checkpoint: string | null;
    completed: number;
    done: boolean;
    waitUntil?: number;
  }>;
  verify(plan: RotationPlan, context: RotationContext): Promise<void>;
  activate(
    plan: RotationPlan,
    context: RotationContext & { session: ClientSession },
  ): Promise<number>;
  verifyActivation(
    plan: RotationPlan,
    context: RotationContext & { session: ClientSession; revision: number },
  ): Promise<void>;
}
export interface RotationStore {
  begin(plan: RotationPlan): Promise<RotationJob>;
  acquire(id: string, owner: string, leaseMs: number): Promise<RotationJob>;
  assertLease(lease: RotationLease): Promise<void>;
  withLease<T>(
    lease: RotationLease,
    work: (session: ClientSession) => Promise<T>,
  ): Promise<T>;
  renew(lease: RotationLease, leaseMs: number): Promise<void>;
  checkpoint(
    lease: RotationLease,
    patch: Partial<RotationJob>,
  ): Promise<RotationJob>;
  complete(
    lease: RotationLease,
    activate: (session: ClientSession) => Promise<number>,
  ): Promise<RotationJob>;
  fail(lease: RotationLease, code?: string): Promise<void>;
  status?(scope: Scope): Promise<RotationStatus | null>;
}
export function createTenantRotationCoordinator(options: {
  store: RotationStore;
  worker: RotationWorker;
  leaseMs?: number;
  batchSize?: number;
}): {
  run(
    plan: RotationPlan,
    options?: {
      signal?: AbortSignal;
      onProgress?: (status: RotationStatus) => void;
    },
  ): Promise<RotationStatus>;
};
export function createMongoTenantRotationStore(options: {
  client: MongoClient;
  database: string;
  clock?: () => number;
}): RotationStore;
export function rotationId(plan: RotationPlan): string;
export function validateRotationPlan(input: unknown): RotationPlan;

export function rotationKeyDigest(scope: Scope, keys: RotationKeys): string;
