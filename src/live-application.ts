import type {
  IncomingMessage,
  ServerResponse,
  RequestListener,
} from 'node:http';

export interface ComposedApplication {
  handler: RequestListener;
  close(): Promise<void>;
}
/** A second ownership count covers requests admitted just before v1→v2 activation. */
export function ownedApplication(application: ComposedApplication) {
  let active = 0,
    closing: Promise<void> | undefined;
  const waiters = new Set<() => void>();
  return {
    handler: application.handler,
    acquire() {
      if (closing) throw Error('Explorer application unavailable');
      active++;
      let released = false;
      return () => {
        if (released) return;
        released = true;
        active--;
        if (!active) for (const resolve of waiters) resolve();
      };
    },
    close() {
      closing ??= (async () => {
        if (active) await new Promise<void>((resolve) => waiters.add(resolve));
        waiters.clear();
        await application.close();
      })();
      return closing;
    },
  };
}
export type OwnedApplication = ReturnType<typeof ownedApplication>;
export function forwardApplication(
  application: OwnedApplication,
  request: IncomingMessage,
  response: ServerResponse,
  signal: AbortSignal,
): Promise<void> {
  const release = application.acquire();
  return new Promise<void>((resolve, reject) => {
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      response.off('finish', finish);
      response.off('close', finish);
      signal.removeEventListener('abort', abort);
      release();
      resolve();
    };
    const abort = () => {
      response.destroy();
      finish();
    };
    response.once('finish', finish);
    response.once('close', finish);
    signal.addEventListener('abort', abort, { once: true });
    if (signal.aborted) {
      abort();
      return;
    }
    try {
      application.handler(request, response);
    } catch (error) {
      finish();
      reject(error);
    }
  });
}
