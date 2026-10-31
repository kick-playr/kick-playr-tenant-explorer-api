/** Explorer exposes global label flags only, never operational team mutations. */
const flags = {
  categories: [
    'isArchived',
    'isInactiveEndOfSeason',
    'isAutoImported',
    'isInactive',
    'is1418Coach',
    'isTrainerChild',
    'isTrainer',
  ],
  branches: [
    'isAnonymized',
    'isTrial',
    'isMustBill',
    'hasTest',
    'isAdmin',
    'isVorstand',
    'hasReceivedClothes',
    'isTrainer',
    'isAthleticTrainer',
    'isGoalieTrainer',
    'isCoach',
    'isCoTrainer',
  ],
} as const;
export function isCatalogMappingRoute(method: string, path: string) {
  if (method === 'GET')
    return /^\/api\/settings\/catalog\/(categories|branches)$/.test(path);
  const match =
    /^\/api\/settings\/catalog\/(categories|branches)\/flags\/([A-Za-z][A-Za-z0-9]{0,63})$/.exec(
      path,
    );
  return (
    method === 'PUT' &&
    !!match &&
    (flags[match[1] as keyof typeof flags] as readonly string[]).includes(
      match[2]!,
    )
  );
}
