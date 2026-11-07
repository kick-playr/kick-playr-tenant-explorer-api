export interface Scope { environment: string; tenant: string }
export interface KeySetDescriptor {
  reference: string;
  mappings: { wrapping: string; index: string; control: string };
  wrappingVersions: { keyVersion: string; vaultVersion: string }[];
  currentWrappingVersion: string;
  indexVersion: string;
  controlVersion: string;
}
export interface SecretDescriptor { mapping: string; purpose: string; version: string }
export interface RuntimeSnapshotRequest {
  schemaVersion: 1; bindingRevision: number; bindingDigest: string;
  keySets: KeySetDescriptor[]; secrets: SecretDescriptor[];
}
export interface Attributes { enabled: boolean; created: number; updated: number; recoveryLevel: 'Purgeable'; nbf?: number; exp?: number }
export interface ResolvedValue { vaultVersion: string; value: string; attributes: Attributes }
export interface RuntimeKeySet {
  reference: string; mappings: KeySetDescriptor['mappings']; currentWrappingVersion: string;
  wrappingVersions: (ResolvedValue & { keyVersion: string })[];
  index: ResolvedValue; control: ResolvedValue;
}
export interface RuntimeSnapshot {
  schemaVersion: 1; environment: string; tenant: string; bindingRevision: number; bindingDigest: string;
  generation: number; loadedAt: number; keySets: RuntimeKeySet[];
  secrets: (SecretDescriptor & { value: string; attributes: Attributes })[];
}
export interface RuntimeManifest { schemaVersion: 1; application: string; scope: Scope; request: RuntimeSnapshotRequest; tenants: { tenant: string; bindingRevision: number; bindingDigest: string }[] }
export interface RuntimeBindings { schemaVersion: 1; applications: Record<string, {scope: Scope; request: RuntimeSnapshotRequest}>; tenants: {scope: Scope; request: RuntimeSnapshotRequest}[] }
export function parseRuntimeManifest(input: unknown): RuntimeManifest;
export type Strategy = 'ENV_VARIABLES' | 'LOCAL_KEYVAULT';
export interface ProcessPolicy { allowedMappings: readonly string[]; requiredMappings?: readonly string[] }
export interface ProcessSecrets { strategy: Strategy; mappings: Readonly<Record<string, string>>; snapshot?: RuntimeSnapshot }
export interface SecretsRuntime {
  load(scope: Scope, request: RuntimeSnapshotRequest): Promise<RuntimeSnapshot>;
  loadApplication(application: string): Promise<{scope: Scope; request: RuntimeSnapshotRequest}>;
  loadTenantBinding?(application:string,tenant:string):Promise<{scope:Scope;request:RuntimeSnapshotRequest}>;
  loadBindings(application: string): Promise<RuntimeBindings>;
  refreshBindings?(application: string): Promise<RuntimeBindings>;
  loadProcess(application: string, policy: ProcessPolicy): Promise<ProcessSecrets>;
  loadTenant(tenant: string, bindingRevision: number): Promise<RuntimeSnapshot>;
  close(): void;
}
export function selectSecretsStrategy(environment?: Record<string, string | undefined>): Strategy;
export function bindingDigest(request: Omit<RuntimeSnapshotRequest, 'bindingDigest'> | RuntimeSnapshotRequest): string;
export function parseSnapshotRequest(input: unknown): RuntimeSnapshotRequest;
export function snapshotMappings(snapshot: RuntimeSnapshot): Readonly<Record<string, string>>;
export function createSecretsRuntime(options: { environment: Record<string, string | undefined>; fetch?: typeof globalThis.fetch; credentialSupplier?: (scope: Readonly<Scope>) => string | Promise<string> }): SecretsRuntime & Required<Pick<SecretsRuntime,'loadTenantBinding'|'refreshBindings'>>;

export interface ApplicationResourceDescriptor { kind: 'secrets'; name: string; mapping: string; policy: string; version: string; classification: 'secret' | 'encryption-key' | 'managed-credential'; attributes: Attributes }
export interface ApplicationDescriptor { schemaVersion: 2; application: string; scope: Scope; generation: number; digest: string; resources: ApplicationResourceDescriptor[] }
export interface ApplicationSnapshot extends Omit<ApplicationDescriptor, 'resources'> { resources: (ApplicationResourceDescriptor & { value: string })[] }
export interface PreparedApplicationValue<T> { value: T; dispose?: () => void | Promise<void> }
export interface ApplicationPrepareContext { previous?: ApplicationSnapshot; previousDescriptor?: ApplicationDescriptor; signal: AbortSignal }
export interface ApplicationRuntimeStatus { state: 'starting' | 'applied' | 'warning' | 'blocked' | 'closed'; reason?: string; generation?: number; digest?: string }
export interface ApplicationRuntime<T> {
  mode(): Promise<'legacy'|'live'>; start(): Promise<void>; refresh(): Promise<void>; close(): void;
  withValue<R>(operation: (value: T, context: Readonly<{ signal: AbortSignal; generation: number; digest: string; scope: Readonly<Scope> }>) => R | Promise<R>): Promise<R>;
  status(): Readonly<ApplicationRuntimeStatus>;
}
export function createApplicationRuntime<T>(options: { application: string; scope: Scope; environment: Record<string,string|undefined>; allowedMappings: readonly string[] | ((mapping: string) => boolean); requiredMappings?: readonly string[]; baseline?: ApplicationDescriptor; initial?: {snapshot: ApplicationSnapshot; prepared: PreparedApplicationValue<T>}; fetch?: typeof globalThis.fetch; credentialSupplier?: (scope: Readonly<Scope>) => string | Promise<string>; intervalMs?: number; operationTimeoutMs?: number; prepare: (snapshot: ApplicationSnapshot, context: ApplicationPrepareContext) => PreparedApplicationValue<T> | Promise<PreparedApplicationValue<T>>; prepareManagedCredential?: (snapshot: ApplicationSnapshot, context: ApplicationPrepareContext) => PreparedApplicationValue<T> | Promise<PreparedApplicationValue<T>>; prepareMigration?: (snapshot: ApplicationSnapshot, context: ApplicationPrepareContext) => PreparedApplicationValue<T> | Promise<PreparedApplicationValue<T>> }): ApplicationRuntime<T>;
export function parseApplicationDescriptor(input: unknown, scope: Scope, application: string): ApplicationDescriptor;
export function parseApplicationDescriptor(input: unknown, scope: Scope, application: string, values: true): ApplicationSnapshot;

export function applicationSnapshotFromLegacy(application: string, snapshot: RuntimeSnapshot): ApplicationSnapshot;

/** Metadata-only legacy pins for migration comparison; never a serving generation. */
export function applicationDescriptorFromLegacy(application: string, scope: Scope, request: RuntimeSnapshotRequest): ApplicationDescriptor;

export function applicationDescriptorFromTenantLegacy(application:string,scope:Scope,request:RuntimeSnapshotRequest):ApplicationDescriptor;
export function applicationSnapshotFromTenantLegacy(application:string,snapshot:RuntimeSnapshot):ApplicationSnapshot;

export * from './tenant-rotation.cjs';
