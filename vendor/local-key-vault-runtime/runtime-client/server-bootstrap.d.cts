import type {
  BootstrapOptions,
  BootstrapSnapshot,
  BootstrapContext,
  BootstrapValue,
} from "./bootstrap.cjs";
export interface ServerBootstrapOptions {
  requiredMappings?: readonly string[];
  onChange?: (
    next: BootstrapSnapshot | undefined,
    previous: BootstrapSnapshot | undefined,
  ) => void | Promise<void>;
  onDiagnostic?: (message: string) => void;
  clientOptions?: Partial<BootstrapOptions>;
}
export interface ServerBootstrap {
  load(): Promise<Readonly<Record<string, string>>>;
  refresh(): Promise<void>;
  status(): {
    state: string;
    ready: boolean;
    connected: boolean;
    message?: string;
    revision?: string;
  };
  tenant(id: string): Readonly<Record<string, string>>;
  integration(tenantId: string, name: string): BootstrapValue;
  context(tenantId?: string): BootstrapContext;
  tenantIds(): string[];
  key(resourceId: string, versionId: string): Buffer;
  close(): void;
}
export function createServerBootstrap(
  environment: Record<string, string | undefined>,
  applicationId: string,
  options?: ServerBootstrapOptions,
): ServerBootstrap;

export function publicConfiguration(
  context: BootstrapContext,
): Readonly<{ clerkPublishableKey?: string; apiOrigin?: string }>;
