import 'dotenv/config';
import { startExplorer } from './startup.js';

startExplorer(process.env).catch(() => {
  console.error(
    'Tenant explorer API startup failed. Check database, Clerk and vault configuration.',
  );
  process.exitCode = 1;
});
