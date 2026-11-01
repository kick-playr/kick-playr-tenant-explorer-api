import type {
  SecretsRuntime,
  RuntimeSnapshot,
  RuntimeKeySet,
  Strategy,
} from '@kick-playr/local-key-vault/runtime-client';
import type { StartupDiagnostics } from './startup-diagnostics.js';

const fail = () => Error('Explorer secrets unavailable');
const restart = () => Error('Tenant secrets require application restart');
const processNames = [
  'EXPLORER_MONGODB_URI',
  'WORKFLOW_SHARED_WRAPPING_KEY_V1',
  'EXPLORER_CREDENTIAL_KEY',
  'MANAGER_SETUP_CONTROL_KEY',
  'CLERK_SECRET_KEY',
  'EXPLORER_INVITATION_SMTP_URL',
] as const;
const requiredNames = processNames.slice(0, 5);
export interface TenantSecretIdentity {
  environment: string;
  tenantId: string;
  configRevision: number;
}
export interface SecretKeyBinding {
  environment: string;
  tenantId: string;
  keyReference: string;
  version?: string;
  variables: { wrapping: string; index: string; control: string };
}
export interface TenantKeySource {
  readonly strategy: Strategy;
  tenantEnvironment(
    binding: SecretKeyBinding,
    revision?: number,
  ): Readonly<Record<string, string | undefined>>;
  describe(
    binding: SecretKeyBinding,
    revision?: number,
  ): { generation: number; version: string; versions: Record<string, string> };
}
function invitationSecretNames(raw: string | undefined): string[] {
  let rows: unknown;
  try {
    rows = JSON.parse(raw ?? '[]');
  } catch {
    throw fail();
  }
  if (!Array.isArray(rows) || rows.length > 128) throw fail();
  const names = rows.map((row) => row?.secretKeyEnv);
  if (
    names.some(
      (name) =>
        typeof name !== 'string' ||
        !/^(?!NEXT_PUBLIC_|VITE_|PUBLIC_)[A-Z][A-Z0-9_]{1,100}$/.test(name),
    )
  )
    throw fail();
  return [...new Set(names)] as string[];
}
function key(value: string | undefined): boolean {
  if (!value || value.length !== 44) return false;
  const b = Buffer.from(value, 'base64');
  try {
    return b.length === 32 && b.toString('base64') === value;
  } finally {
    b.fill(0);
  }
}
export class ExplorerSecrets implements TenantKeySource {
  private readonly snapshots = new Map<string, RuntimeSnapshot>();
  private closed = false;
  constructor(
    readonly strategy: Strategy,
    readonly environment: NodeJS.ProcessEnv,
    private readonly runtime: SecretsRuntime,
  ) {}
  async initializeTenant(identity: TenantSecretIdentity) {
    if (this.strategy !== 'LOCAL_KEYVAULT') return;
    if (
      this.closed ||
      identity.environment !== 'development' ||
      !Number.isSafeInteger(identity.configRevision) ||
      identity.configRevision < 1
    )
      throw fail();
    const snapshot = await this.runtime.loadTenant(
      identity.tenantId,
      identity.configRevision,
    );
    if (
      snapshot.tenant !== identity.tenantId ||
      snapshot.environment !== identity.environment ||
      snapshot.bindingRevision !== identity.configRevision
    )
      throw fail();
    const id = `${identity.environment}/${identity.tenantId}`;
    if (this.snapshots.has(id)) throw fail();
    this.snapshots.set(id, Object.freeze(structuredClone(snapshot)));
  }
  private set(
    binding: SecretKeyBinding,
    revision?: number,
  ): { snapshot: RuntimeSnapshot; set: RuntimeKeySet } {
    if (this.closed) throw restart();
    const snapshot = this.snapshots.get(
      `${binding.environment}/${binding.tenantId}`,
    );
    if (
      !snapshot ||
      (revision !== undefined && revision !== snapshot.bindingRevision)
    )
      throw restart();
    const set = snapshot.keySets.find(
      (s) => s.reference === binding.keyReference,
    );
    if (
      !set ||
      Object.keys(binding.variables).some(
        (k) =>
          binding.variables[k as keyof typeof binding.variables] !==
          set.mappings[k as keyof typeof set.mappings],
      )
    )
      throw restart();
    return { snapshot, set };
  }
  tenantEnvironment(
    binding: SecretKeyBinding,
    revision?: number,
  ): Readonly<Record<string, string | undefined>> {
    if (this.strategy === 'ENV_VARIABLES') return this.environment;
    const { set } = this.set(binding, revision);
    const wrap = set.wrappingVersions.find(
      (w) => w.keyVersion === set.currentWrappingVersion,
    );
    const values = [wrap?.value, set.index.value, set.control.value];
    if (!values.every(key) || new Set(values).size !== 3) throw fail();
    return Object.freeze({
      [binding.variables.wrapping]: values[0],
      [binding.variables.index]: values[1],
      [binding.variables.control]: values[2],
    });
  }
  describe(binding: SecretKeyBinding, revision?: number) {
    const { snapshot, set } = this.set(binding, revision);
    const wrap = set.wrappingVersions.find(
      (w) => w.keyVersion === set.currentWrappingVersion,
    );
    if (!wrap) throw fail();
    return {
      generation: snapshot.generation,
      version: set.currentWrappingVersion,
      versions: {
        wrapping: wrap.vaultVersion,
        index: set.index.vaultVersion,
        control: set.control.vaultVersion,
      },
    };
  }
  /** Resolve only explicit vault mapping references, never plaintext tenant credentials. */
  secret(identity: TenantSecretIdentity, reference: unknown): string {
    if (this.strategy !== 'LOCAL_KEYVAULT') throw fail();
    if (
      typeof reference !== 'string' ||
      !/^vault:[A-Z][A-Z0-9_]{1,127}$/.test(reference)
    )
      throw fail();
    const snapshot = this.snapshots.get(
      `${identity.environment}/${identity.tenantId}`,
    );
    if (!snapshot || snapshot.bindingRevision !== identity.configRevision)
      throw restart();
    const found = snapshot.secrets.find(
      (s) => s.mapping === reference.slice(6),
    );
    if (!found || !found.value) throw fail();
    return found.value;
  }
  close() {
    this.closed = true;
    this.snapshots.clear();
    this.runtime.close();
  }
}
export async function createExplorerSecrets(
  environment: NodeJS.ProcessEnv,
  injected?: SecretsRuntime,
  diagnostics?: StartupDiagnostics,
): Promise<ExplorerSecrets> {
  const strategy = environment.SECRETS_KEYS_STRATEGY ?? 'ENV_VARIABLES';
  if (!['ENV_VARIABLES', 'LOCAL_KEYVAULT'].includes(strategy)) throw fail();
  const runtime =
    injected ??
    (
      await import('@kick-playr/local-key-vault/runtime-client')
    ).createSecretsRuntime({
      environment,
      fetch: diagnostics
        ? (input, init) => {
            const url = new URL(
              typeof input === 'string'
                ? input
                : input instanceof URL ? input.href : input.url,
            );
            const operation = url.pathname.startsWith('/local/runtime-manifests/')
              ? 'manifest' : 'snapshot';
            return diagnostics.vaultRequest(
              () => globalThis.fetch(input, init), operation,
            );
          }
        : undefined,
    });
  try {
    if (strategy === 'ENV_VARIABLES')
      return new ExplorerSecrets(strategy, { ...environment }, runtime);
    if (
      environment.NODE_ENV !== 'development' ||
      environment.VERCEL !== undefined ||
      environment.AWS_LAMBDA_FUNCTION_NAME !== undefined
    )
      throw fail();
    const invitationNames = invitationSecretNames(
      environment.EXPLORER_INVITATION_BINDINGS_JSON,
    );
    const allowedMappings = [...new Set([...processNames, ...invitationNames])];
    const loaded = await runtime.loadProcess('explorer-api', {
      allowedMappings,
      requiredMappings: [...requiredNames, ...invitationNames],
    });
    if (
      loaded.strategy !== strategy ||
      requiredNames.some((name) => !loaded.mappings[name]) ||
      Object.keys(loaded.mappings).some(
        (name) => !allowedMappings.includes(name),
      )
    )
      throw fail();
    if (
      !key(loaded.mappings.WORKFLOW_SHARED_WRAPPING_KEY_V1) ||
      !key(loaded.mappings.MANAGER_SETUP_CONTROL_KEY) ||
      !/^[a-fA-F0-9]{64}$/.test(loaded.mappings.EXPLORER_CREDENTIAL_KEY ?? '')
    )
      throw fail();
    if (
      loaded.mappings.WORKFLOW_SHARED_WRAPPING_KEY_V1 ===
      loaded.mappings.MANAGER_SETUP_CONTROL_KEY
    )
      throw fail();
    for (const name of [
      'EXPLORER_MONGODB_URI',
      'EXPLORER_INVITATION_SMTP_URL',
    ]) {
      const value = loaded.mappings[name];
      if (value && (value !== value.trim() || /[\x00-\x20\x7f]/.test(value)))
        throw fail();
    }
    const captured = { ...environment };
    for (const name of Object.keys(captured))
      if (
        allowedMappings.includes(name) ||
        /(?:WRAPPING_KEY_V\d+|INDEX_KEY|CONTROL_KEY)$/.test(name)
      )
        delete captured[name];
    Object.assign(captured, loaded.mappings);
    return new ExplorerSecrets(strategy, Object.freeze(captured), runtime);
  } catch {
    runtime.close();
    throw fail();
  }
}
