import { type ExplorerSecrets } from './secrets.js';
import { StartupDiagnostics } from './startup-diagnostics.js';
/** This barrier precedes import of Clerk, Mongo clients and Nest composition. */
export async function startExplorer(
  environment: NodeJS.ProcessEnv,
  load: ((
    env: NodeJS.ProcessEnv,
    diagnostics?: StartupDiagnostics,
  ) => Promise<ExplorerSecrets>) | undefined = undefined,
  initialize: () => Promise<{
    bootstrap: (secrets: ExplorerSecrets, diagnostics?: StartupDiagnostics) => Promise<void>;
  }> = () => import('./bootstrap.js'),
  output?: (event: Readonly<Record<string, unknown>>) => void,
) {
  const diagnostics = new StartupDiagnostics(output);
  diagnostics.configuration(environment);
  if (!load) {
    const { startLiveExplorer } = await import('./live-explorer.js');
    await startLiveExplorer(environment, diagnostics);
    return;
  }
  const secrets = await diagnostics.run('secrets.process', async () => {
    const loaded = await load(environment, diagnostics);
    if (!loaded) throw Error('Explorer secrets unavailable');
    return loaded;
  });
  try {
    const server = await diagnostics.run('server.import', initialize);
    await diagnostics.run('server.bootstrap', () => server.bootstrap(secrets, diagnostics));
  } catch (error) {
    secrets.close();
    throw error;
  }
}
