import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import type { Envelope } from './contracts.js';

/** Explorer control-plane custody. No HTTP secret retrieval is exposed. */
export class CredentialVault {
  private readonly key: Buffer;
  constructor(key: Buffer) {
    if (key.length !== 32)
      throw new Error('EXPLORER_CREDENTIAL_KEY must contain exactly 32 bytes');
    this.key = Buffer.from(key);
  }
  seal(binding: string, value: string): Envelope {
    const nonce = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.key, nonce);
    cipher.setAAD(Buffer.from(`explorer-credential-v1:${binding}`));
    const ciphertext = Buffer.concat([
      cipher.update(value, 'utf8'),
      cipher.final(),
    ]);
    return {
      version: 1,
      nonce: nonce.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
      tag: cipher.getAuthTag().toString('base64'),
    };
  }
  open(binding: string, envelope: Envelope): string {
    if (envelope.version !== 1)
      throw new Error('Unsupported credential envelope');
    const cipher = createDecipheriv(
      'aes-256-gcm',
      this.key,
      Buffer.from(envelope.nonce, 'base64'),
    );
    cipher.setAAD(Buffer.from(`explorer-credential-v1:${binding}`));
    cipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
    return Buffer.concat([
      cipher.update(Buffer.from(envelope.ciphertext, 'base64')),
      cipher.final(),
    ]).toString('utf8');
  }
}
