/** Fixed club team commands; existing identity replacement is deliberately absent. */
export function isClubTeamRoute(method: string, path: string): boolean {
  if (method === 'GET')
    return /^\/api\/settings\/teams(?:\/readiness)?$/.test(path);
  if (method === 'PUT')
    return path === '/api/settings/catalog/categories/team-seasons';
  return (
    method === 'POST' &&
    (path === '/api/settings/teams/create' ||
      /^\/api\/settings\/teams\/[1-9][0-9]*\/refresh$/.test(path) ||
      /^\/api\/settings\/teams\/operations\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/resume$/i.test(
        path,
      ))
  );
}
