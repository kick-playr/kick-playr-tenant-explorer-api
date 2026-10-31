export interface SetupProgress {
  step: 'settings' | 'bexio' | 'contact' | 'review';
  contactId?: number;
  contactAccountReference?: string;
  confirmedBy?: string;
  settingsHash?: string;
  completedAt?: string;
}
export interface OnboardingState {
  policyVersion: string;
  ownerCompletedAt?: string;
  progress: Record<string, SetupProgress>;
  operatorSteps?: string[];
  provisioning?: {
    configRevision: number;
    verifiedAt: string;
    checks: Record<string, string>;
  };
}
export interface RuntimePublication {
  accountReference: string;
  expiresAt?: number;
  proofId: string;
  membershipId: string;
  issuer: string;
  subject: string;
  contactId: number;
  role: 'owner' | 'main-manager' | 'manager';
}
