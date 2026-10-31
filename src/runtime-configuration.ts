import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
export const MAX_RUNTIME_BYTES = 2 * 1024 * 1024;
export interface RuntimeEnvelope {
  _id: 'runtime:development';
  version: 1;
  nonce: string;
  ciphertext: string;
  tag: string;
}
const unavailable = () => Error('Runtime configuration unavailable');
function aad(key: Buffer, database: string) {
  if (key.length !== 32 || !/^[A-Za-z0-9_-]{1,63}$/.test(database))
    throw unavailable();
  return Buffer.from(
    JSON.stringify(['kick-playr:tenant-workflow-configuration', database, 1]),
  );
}
function bytes(value: unknown, max: number, exact?: number) {
  if (
    typeof value !== 'string' ||
    !value ||
    value.length > Math.ceil(max / 3) * 4
  )
    throw unavailable();
  const decoded = Buffer.from(value, 'base64');
  if (
    decoded.length > max ||
    decoded.toString('base64') !== value ||
    (exact !== undefined && decoded.length !== exact)
  )
    throw unavailable();
  return decoded;
}
export function decodeRuntimeEnvelope(
  row: unknown,
  key: Buffer,
  database: string,
): Record<string, unknown> {
  let plain: Buffer | undefined;
  try {
    const r = row as RuntimeEnvelope;
    if (
      !r ||
      Object.keys(r).sort().join() !== '_id,ciphertext,nonce,tag,version' ||
      r._id !== 'runtime:development' ||
      r.version !== 1
    )
      throw unavailable();
    const decipher = createDecipheriv(
      'aes-256-gcm',
      key,
      bytes(r.nonce, 12, 12),
    );
    decipher.setAAD(aad(key, database));
    decipher.setAuthTag(bytes(r.tag, 16, 16));
    plain = Buffer.concat([
      decipher.update(bytes(r.ciphertext, MAX_RUNTIME_BYTES)),
      decipher.final(),
    ]);
    if (plain.length > MAX_RUNTIME_BYTES) throw unavailable();
    const value: unknown = JSON.parse(plain.toString('utf8'));
    if (!value || typeof value !== 'object' || Array.isArray(value))
      throw unavailable();
    return value as Record<string, unknown>;
  } catch {
    throw unavailable();
  } finally {
    plain?.fill(0);
  }
}
export function encodeRuntimeEnvelope(
  value: unknown,
  key: Buffer,
  database: string,
): RuntimeEnvelope {
  let plain: Buffer | undefined;
  try {
    plain = Buffer.from(JSON.stringify(value), 'utf8');
    if (plain.length > MAX_RUNTIME_BYTES) throw unavailable();
    const nonce = randomBytes(12),
      cipher = createCipheriv('aes-256-gcm', key, nonce);
    cipher.setAAD(aad(key, database));
    const ciphertext = Buffer.concat([cipher.update(plain), cipher.final()]);
    return {
      _id: 'runtime:development',
      version: 1,
      nonce: nonce.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
      tag: cipher.getAuthTag().toString('base64'),
    };
  } catch {
    throw unavailable();
  } finally {
    plain?.fill(0);
  }
}
