export interface BootstrapValue {
  readonly resourceId: string;
  readonly versionId: string;
  readonly name: string;
  readonly accessName: string;
  readonly kind: "secret" | "encryption-key" | "integration";
  readonly valueFormat: "text" | "base64" | "hex64";
  readonly schemaIdentity: string;
  readonly value: string | Readonly<Record<string, unknown>>;
  readonly schema?: Record<string, unknown>;
  readonly keyVersions?: readonly {
    versionId: string;
    state: "prepared" | "active-for-encryption" | "decrypt-only";
    value: string;
    rotationId?: string;
    keyLabel?: string;
  }[];
}
export interface BootstrapContext {
  readonly ready: boolean;
  readonly reason?: string;
  readonly values: readonly BootstrapValue[];
}
export interface BootstrapSnapshot {
  readonly format: 2;
  readonly applicationId: string;
  readonly environment: string;
  readonly revision: string;
  readonly application: BootstrapContext;
  readonly tenants: Readonly<Record<string, BootstrapContext>>;
}
export interface BootstrapOptions {
  url: string;
  applicationId: string;
  environment: string;
  grant: string;
  refreshIntervalMs?: number;
  registerInstances?: boolean;
  requiredMappings?: readonly string[];
  acknowledgeKey?: (
    resource: BootstrapValue,
    key: {
      versionId: string;
      state: string;
      value: string;
      rotationId?: string;
      keyLabel?: string;
    },
  ) => boolean | Promise<boolean>;
  timeoutMs?: number;
  env?: Record<string, string | undefined>;
  fetch?: typeof fetch;
  now?: () => number;
  schedule?: (callback: () => void, delay: number) => () => void;
  onChange?: (
    next: BootstrapSnapshot | undefined,
    previous: BootstrapSnapshot | undefined,
  ) => void | Promise<void>;
  onDiagnostic?: (message: string) => void;
}
export interface BootstrapClient {
  start(): Promise<void>;
  refresh(): Promise<void>;
  status(): Readonly<{
    ready: boolean;
    connected: boolean;
    message?: string;
    revision?: string;
  }>;
  application(): BootstrapContext;
  tenant(id: string): BootstrapContext;
  tenantIds(): string[];
  key(resourceId: string, versionId: string): Buffer;
  close(): void;
}
export function createBootstrapClient(
  options: BootstrapOptions,
): BootstrapClient;
