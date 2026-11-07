/** Only provider callback fields are allowed; destinations never come from queries. */
export function oauthCallbackPath(provider: string, query: Record<string,unknown>): string {
  const base = provider === 'bexio' ? '/bexio/oauth/callback' : provider === 'dropbox' ? '/dropbox/authorize' : undefined;
  if (!base) throw Error('Invalid provider');
  const allowed = provider === 'bexio' ? ['state','code','iss','session_state'] : ['state','code'];
  const params = new URLSearchParams();
  for (const [key,value] of Object.entries(query)) {
    if (!allowed.includes(key) || typeof value !== 'string' || !value || value.length > 8192) throw Error('Invalid callback');
    params.set(key,value);
  }
  if (!/^oauth1\.[A-Za-z0-9_-]{43}$/.test(params.get('state') ?? '') || !params.get('code') ||
      (params.has('iss') && params.get('iss') !== 'https://auth.bexio.com/realms/bexio')) throw Error('Invalid callback');
  return base+'?'+params;
}
