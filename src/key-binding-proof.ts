import { createHmac } from 'node:crypto';
export const KEY_KINDS = ['wrapping', 'index', 'control'] as const;
export type KeyKind = (typeof KEY_KINDS)[number];
export interface KeyProofBinding {
  environment: string;
  tenantId: string;
  configRevision: number;
  keyReference: string;
  expiresAt: number;
}
export function keyBindingProof(
  key: Buffer,
  b: KeyProofBinding,
  challenge: string,
  kind: KeyKind,
  variable: string,
) {
  return createHmac('sha256', key)
    .update(
      JSON.stringify([
        'manager-key-binding-v1',
        b.environment,
        b.tenantId,
        b.configRevision,
        b.keyReference,
        b.expiresAt,
        challenge,
        kind,
        variable,
      ]),
    )
    .digest('base64url');
}
