import { createExplorerSecrets, type ExplorerSecrets } from './secrets.js';
/** This barrier precedes import of Clerk, Mongo clients and Nest composition. */
export async function startExplorer(
  environment: NodeJS.ProcessEnv,
  load: (
    env: NodeJS.ProcessEnv,
  ) => Promise<ExplorerSecrets> = createExplorerSecrets,
  initialize: () => Promise<{
    bootstrap: (secrets: ExplorerSecrets) => Promise<void>;
  }> = () => import('./bootstrap.js'),
) {
  const secrets = await load(environment);
  try {
    await (await initialize()).bootstrap(secrets);
  } catch (error) {
    secrets.close();
    throw error;
  }
}
