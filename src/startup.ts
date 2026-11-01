import { createExplorerSecrets, type ExplorerSecrets } from './secrets.js';
import { StartupDiagnostics } from './startup-diagnostics.js';
/** This barrier precedes import of Clerk, Mongo clients and Nest composition. */
export async function startExplorer(
  environment: NodeJS.ProcessEnv,
  load: (
    env: NodeJS.ProcessEnv,
    diagnostics?: StartupDiagnostics,
  ) => Promise<ExplorerSecrets> = (env, diagnostics) => createExplorerSecrets(env, undefined, diagnostics),
  initialize: () => Promise<{
    bootstrap: (secrets: ExplorerSecrets, diagnostics?: StartupDiagnostics) => Promise<void>;
  }> = () => import('./bootstrap.js'),
  output?: (event: Readonly<Record<string, unknown>>) => void,
) {
  const diagnostics = new StartupDiagnostics(output);
  diagnostics.configuration(environment);
  const secrets = await diagnostics.run('secrets.process', () => load(environment, diagnostics));
  try {
    const server = await diagnostics.run('server.import', initialize);
    await diagnostics.run('server.bootstrap', () => server.bootstrap(secrets, diagnostics));
  } catch (error) {
    secrets.close();
    throw error;
  }
}
