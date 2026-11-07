export interface RuntimeCredential {
  accessToken: string;
  refreshToken: string;
  idToken?: string;
  tokenType?: string;
  expiresAt: number;
}
export interface RuntimeLifecycleMetadata {
  schema: 1;
  connectionId: string;
  provider: string;
  purpose: string;
  capabilities: readonly string[];
  securityEpoch: number;
}
export interface RuntimeAuthoritySnapshot {
  expiresAt: number;
  authorityGeneration: number;
  revision: number;
  staticVersion: string;
  accountReference: string;
  status: "active" | "suspended" | "revoked" | "reauthorization-required";
  operation: string | null;
  metadata?: RuntimeLifecycleMetadata;
}
export interface RuntimeOptions {
  /** Transaction-only authorization fence. Must not dispatch external side effects. */
  beforeWrite?: (session: any) => Promise<void>;
  cache?: {
    get(key: string): Promise<unknown>;
    set(key: string, value: unknown, ttlMs: number): Promise<void>;
  };
  db: any;
  tenantId: string;
  environment: string;
  integrationId: string;
  staticVersion: string;
  accountReference: string;
  keys: ReadonlyMap<string, Buffer>;
  activeKeyVersion: string;
}
export function createIntegrationRuntime(options: RuntimeOptions): Readonly<{
  token(): Promise<RuntimeCredential>;
  inspect(): Promise<Readonly<RuntimeAuthoritySnapshot> | null>;
  setLifecycle(
    expectedGeneration: number,
    expectedRevision: number,
    status: "active" | "suspended",
    metadata: RuntimeLifecycleMetadata,
  ): Promise<{ revision: number; authorityGeneration: number }>;
  recoverReserved(operationId: string): Promise<{ recovered: true }>;
  synchronizeStatic(
    expectedGeneration: number,
  ): Promise<{ status: string; authorityGeneration: number }>;
  refresh(
    provider: (old: RuntimeCredential) => Promise<RuntimeCredential>,
    expected?: {
      authorityGeneration: number;
      revision: number;
      force?: boolean;
    },
  ): Promise<RuntimeCredential>;
  reconnect(
    value: RuntimeCredential,
    verifiedAccountReference: string,
    expectedGeneration: number,
    lifecycle?: {
      expectedRevision?: number;
      metadata?: RuntimeLifecycleMetadata;
    },
  ): Promise<{ revision: number; authorityGeneration: number }>;
  revoke(expectedGeneration: number): Promise<void>;
}>;
export function assertRuntimeDatabase(database: string, tenantId: string): void;

export function validateRuntimeMetadata(
  input: unknown,
): RuntimeLifecycleMetadata;
