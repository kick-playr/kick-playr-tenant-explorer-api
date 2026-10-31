import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { Readable } from 'node:stream';

/** Node's Fetch can replace Host with the connection address. Preserve the
 * server-configured virtual host when connecting to a loopback tenant proxy. */
export const runtimeTransport: typeof fetch = async (input, init) => {
  const url = new URL(String(input));
  if (
    !['http:', 'https:'].includes(url.protocol) ||
    (init?.body !== undefined && typeof init.body !== 'string')
  )
    throw Error('Invalid runtime transport request');
  const headers = new Headers(init?.headers);
  headers.set('accept-encoding', 'identity');
  headers.set(
    'content-length',
    String(Buffer.byteLength(typeof init?.body === 'string' ? init.body : '')),
  );
  return new Promise<Response>((resolve, reject) => {
    const request = (url.protocol === 'https:' ? httpsRequest : httpRequest)(
      url,
      {
        method: init?.method ?? 'GET',
        headers: Object.fromEntries(headers),
        signal: init?.signal ?? undefined,
      },
      (response) => {
        const output = new Headers();
        for (const [key, value] of Object.entries(response.headers)) {
          if (value !== undefined)
            output.set(key, Array.isArray(value) ? value.join(',') : value);
        }
        try {
          resolve(
            new Response(
              Readable.toWeb(response) as ReadableStream<Uint8Array>,
              { status: response.statusCode ?? 502, headers: output },
            ),
          );
        } catch (error) {
          response.destroy();
          reject(error);
        }
      },
    );
    request.on('error', reject);
    request.end(init?.body);
  });
};
