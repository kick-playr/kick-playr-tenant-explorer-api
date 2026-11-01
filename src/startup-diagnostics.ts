type Stage = 'secrets.process' | 'server.import' | 'server.bootstrap' | 'configuration' |
  'database.connect' | 'database.configuration' | 'secrets.tenants' | 'application.compose' | 'server.listen';
type Event = Readonly<Record<string, unknown>>;
const hints: Record<Stage, string> = {
  'secrets.process': 'Check NODE_ENV, strategy, vault authentication, bindings, pinned versions and required process mappings.',
  'server.import': 'Check installed dependencies; install from the current lockfile.',
  'server.bootstrap': 'See the last failed startup stage; check server and Clerk realm configuration.',
  configuration: 'Check EXPLORER_CONTROL_DATABASE, EXPLORER_CREDENTIAL_KEY, WORKFLOW_SHARED_WRAPPING_KEY_V1, EXPLORER_MONGODB_URI and PORT.',
  'database.connect': 'Check MongoDB reachability, DNS, TLS and authentication.',
  'database.configuration': 'Check the selected control database and the original shared configuration wrapping key.',
  'secrets.tenants': 'Check tenant namespaces, current revisions, key references, read grants and pinned vault versions.',
  'application.compose': 'Check Clerk realm configuration and server dependencies.',
  'server.listen': 'Check HOST, PORT and whether the port is already in use.',
};
function safeCode(error: unknown): string | undefined {
  const value = error as { code?: unknown; cause?: { code?: unknown } } | undefined;
  const known = ['ERR_MODULE_NOT_FOUND', 'MODULE_NOT_FOUND', 'EADDRINUSE', 'ECONNREFUSED', 'ENOTFOUND', 'EAI_AGAIN', 'ETIMEDOUT', 'ECONNRESET', 'CERT_HAS_EXPIRED', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE'];
  for (const code of [value?.code, value?.cause?.code]) {
    if (typeof code === 'string' && known.includes(code)) return code;
    if (code === 18) return 'MONGODB_AUTHENTICATION_FAILED';
    if (code === 13) return 'MONGODB_AUTHORIZATION_DENIED';
  }
  return undefined;
}
/** Emit only caller-independent fields selected here; never errors, URLs or env values. */
export class StartupDiagnostics {
  constructor(private readonly output: (event: Event) => void = event => console.info(JSON.stringify(event))) {}
  private emit(event: Event) {
    try { this.output(Object.freeze(event)); } catch { /* Observation cannot break startup/cleanup. */ }
  }
  configuration(environment: NodeJS.ProcessEnv) {
    const selected = environment.SECRETS_KEYS_STRATEGY ?? 'ENV_VARIABLES';
    const strategy = ['ENV_VARIABLES', 'LOCAL_KEYVAULT'].includes(selected) ? selected : 'invalid';
    const nodeEnvironment = ['development', 'test', 'production'].includes(environment.NODE_ENV ?? '') ? environment.NODE_ENV : environment.NODE_ENV === undefined ? 'unset' : 'invalid';
    const required = strategy === 'LOCAL_KEYVAULT' ? ['NODE_ENV', 'LOCAL_KEYVAULT_AUTH_JSON'] : [];
    const missing = required.filter(name => !environment[name]);
    const invalid: string[] = [];
    if (strategy === 'invalid') invalid.push('SECRETS_KEYS_STRATEGY');
    if (strategy === 'LOCAL_KEYVAULT' && environment.NODE_ENV && environment.NODE_ENV !== 'development') invalid.push('NODE_ENV');
    for (const name of ['LOCAL_KEYVAULT_AUTH_JSON', 'LOCAL_KEYVAULT_BINDINGS_JSON']) {
      if (strategy !== 'LOCAL_KEYVAULT' || !environment[name]) continue;
      try {
        const value = JSON.parse(environment[name]!);
        if (!value || typeof value !== 'object' || Array.isArray(value) || value.schemaVersion !== 1) invalid.push(name);
        else if (name === 'LOCAL_KEYVAULT_AUTH_JSON' && (!Array.isArray(value.grants) || !value.grants.length)) invalid.push(name);
        else if (name === 'LOCAL_KEYVAULT_BINDINGS_JSON' && !value.applications?.['explorer-api']) invalid.push(name + '.applications.explorer-api');
      } catch { invalid.push(name); }
    }
    this.emit({ event: 'explorer.startup.configuration', strategy, nodeEnvironment, missing, invalid,
      bindingSource: environment.LOCAL_KEYVAULT_BINDINGS_JSON ? 'environment' : 'vault-manifest',
      vaultUrlConfigured: Boolean(environment.LOCAL_KEYVAULT_URL),
      hint: missing.length || invalid.length ? 'Fix the named settings; no secret values are shown. Existing environment credentials are not a vault fallback.' : 'Basic configuration presence checked; full validation follows.' });
  }
  async run<T>(stage: Stage, work: () => Promise<T>): Promise<T> {
    const start = performance.now();
    this.emit({ event: 'explorer.startup.stage', stage, phase: 'begin' });
    try {
      const result = await work();
      this.emit({ event: 'explorer.startup.stage', stage, phase: 'success', durationMs: Math.round(performance.now() - start) });
      return result;
    } catch (error) {
      this.emit({ event: 'explorer.startup.stage', stage, phase: 'failure', durationMs: Math.round(performance.now() - start), code: safeCode(error), hint: hints[stage] });
      throw error;
    }
  }
  async vaultRequest(work: () => Promise<Response>, operation: 'manifest' | 'snapshot' = 'snapshot'): Promise<Response> {
    const start = performance.now();
    this.emit({ event: 'explorer.startup.vault-request', operation, phase: 'begin' });
    try {
      const response = await work();
      this.emit({ event: 'explorer.startup.vault-request', operation, phase: response.ok ? 'success' : 'failure',
        status: response.status, durationMs: Math.round(performance.now() - start),
        hint: response.ok ? undefined : response.status === 404 && operation === 'manifest' ? 'Publish the application runtime manifest in the selected namespace before startup.' : response.status === 404 ? 'Check that the pinned snapshot versions exist in the selected namespace.' : response.status === 401 || response.status === 403 ? 'Check the exact namespace and read-only grant; token values are not logged.' : 'Check vault availability and the pinned snapshot request.' });
      return response;
    } catch (error) {
      this.emit({ event: 'explorer.startup.vault-request', operation, phase: 'failure', durationMs: Math.round(performance.now() - start), code: safeCode(error), hint: 'Check that the vault API is running at LOCAL_KEYVAULT_URL and reachable.' });
      throw error;
    }
  }
}
