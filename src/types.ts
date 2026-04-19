/** P-256 JWK public key (EC, crv P-256). */
export interface P256Jwk {
  kty: 'EC';
  crv: 'P-256';
  x: string;
  y: string;
}

/** cnf.jwk holder binding — agent P-256 public key embedded in the SD-JWT. */
export interface CnfJwk {
  jwk: P256Jwk;
}

/** Bitstring Status List entry from the SD-JWT credentialStatus claim. */
export interface CredentialStatusEntry {
  id: string;
  type: 'BitstringStatusListEntry';
  statusListIndex: number;
  statusListCredential: string;
}

/**
 * I2H2A SD-JWT issuer JWT payload — always-visible claims.
 * Selectively disclosable claims are not present here; they arrive via disclosures.
 */
export interface I2H2AIssuerPayload {
  iss: string;
  sub: string;
  iat: number;
  nbf?: number;
  exp: number;
  vct: 'I2H2A';
  cnf: CnfJwk;
  credentialStatus?: CredentialStatusEntry;
  _sd_alg: 'sha-256';
  _sd: string[];
}

/** KB-JWT payload — agent-signed holder binding. */
export interface KbJwtPayload {
  iat: number;
  aud: string;
  nonce: string;
  sd_hash: string;
}

/**
 * Disclosed claims extracted from SD-JWT disclosures after hash verification.
 * All selectively disclosable I2H2A fields.
 */
export interface I2H2ADisclosedClaims {
  delegatedBy?: string;
  parentCredential?: string | null;
  delegationDepth?: number;
  'scope.mcpServers'?: string[];
  'scope.taskType'?: string;
  authorization?: unknown;
}

/** W3C DID verification method (subset used for issuer key resolution). */
export interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyJwk?: P256Jwk;
  publicKeyMultibase?: string;
}

/** W3C DID Document (subset used for verification). */
export interface DIDDocument {
  id: string;
  verificationMethod?: VerificationMethod[];
  assertionMethod?: (string | VerificationMethod)[];
  authentication?: (string | VerificationMethod)[];
}

/** Result returned by verifyI2H2APresentation. */
export interface VerificationResult {
  valid: boolean;
  error?: string;
  claims?: I2H2AClaims;
}

/** Verified claims available to the MCP server after successful verification. */
export interface I2H2AClaims {
  agentDid: string;
  delegatedBy: string;
  scope: {
    mcpServers: string[];
    taskType: string;
  };
  authorization: unknown;
}

/** Options passed to verifyI2H2APresentation. */
export interface VerifyOptions {
  /** Verifier audience — must match aud in KB-JWT. */
  mcpServerId: string;
  /** Challenge nonce — must match nonce in KB-JWT. */
  nonce: string;
  /** Skip Bitstring Status List revocation check (useful for testing). */
  skipStatusCheck?: boolean;
  /** Override DID resolver URL (default: https://dev.uniresolver.io/1.0/identifiers/). */
  resolverUrl?: string;
}
