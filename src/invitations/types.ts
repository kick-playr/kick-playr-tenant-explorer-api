import type { Envelope } from '../contracts.js';
export interface Scope {
  environment: string;
  tenantId: string;
}
export interface RealmBinding extends Scope {
  issuer: string;
  origin: string;
  audience: string;
  authorizedParties: string[];
  secretKey: string;
}
export interface Identity {
  issuer: string;
  subject: string;
  sessionId: string;
  emails: string[];
}
export type Manager =
  | { kind: 'platform'; issuer: string; subject: string }
  | { kind: 'club'; token: string };
export type Recipient =
  { kind: 'email'; email: string } | { kind: 'subject'; subject: string };
export interface Principal {
  id: string;
  issuer: string;
  subject: string;
  state: 'setup-only' | 'operational' | 'revoked';
  role: 'owner' | 'main-manager' | 'manager';
}
export interface Invitation {
  id: string;
  tokenHash: string;
  version: number;
  expectedIssuer: string;
  recipient: Recipient;
  email: string;
  inviter: string;
  expiresAt: number;
  state: 'pending' | 'accepted' | 'revoked';
  bootstrap: boolean;
  accepted?: {
    issuer: string;
    subject: string;
    membershipId: string;
    at: string;
  };
  delivery: {
    status: 'queued' | 'sending' | 'accepted' | 'failed';
    attempts: number;
    envelope?: Envelope;
    leaseUntil?: number;
    leaseId?: string;
  };
}
export interface InvitationState {
  rates?: { actor: string; times: number[] }[];
  lastEvent?: { action: string; actor: string; resource: string };
  revision: number;
  invitations: Invitation[];
  principals: Principal[];
  owner?: { issuer: string; subject: string };
  bootstrapInvitationId?: string;
}
export interface InvitationTransaction {
  revokeRuntime?: (issuer: string, subject: string) => Promise<void>;
  tenant: {
    definition: {
      id: string;
      environment: string;
      status: string;
      configRevision: number;
      public: { name: string };
    };
    authority: {
      status?: string;
      identityRealm: string;
      users: { issuer: string; subject: string; status: string }[];
    } | null;
  };
  state: InvitationState;
}
export interface InvitationRepository {
  transact<T>(
    scope: Scope,
    work: (tx: InvitationTransaction) => Promise<T>,
  ): Promise<T>;
}
export interface IdentityPort {
  verify(binding: RealmBinding, token: string): Promise<Identity>;
  resolve(binding: RealmBinding, subject: string): Promise<Identity>;
}
export interface DeliveryPort {
  ready?: boolean;
  send(message: {
    to: string;
    url: string;
    club: string;
    id: string;
  }): Promise<void>;
}
