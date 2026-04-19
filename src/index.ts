export { verifyI2H2APresentation } from './verify-vp';
export { resolveDidDocument } from './resolve-did';
export { checkCredentialStatus } from './check-status';
export { validateDelegationScope } from './validate-scope';

export type {
  VerificationResult,
  VerifyOptions,
  I2H2AClaims,
  I2H2ADisclosedClaims,
  I2H2AIssuerPayload,
  KbJwtPayload,
  CredentialStatusEntry,
  DIDDocument,
  VerificationMethod,
  P256Jwk,
  CnfJwk,
} from './types';
