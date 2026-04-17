/**
 * W3C Verifiable Credentials Data Model 2.0–aligned types (URIs, JSON-LD terms).
 * @see https://www.w3.org/TR/vc-data-model-2.0/
 */

/** JSON-LD @context entry: URI string or inline context object. */
export type JsonLdContext = string | Record<string, unknown> | Array<string | Record<string, unknown>>;

/** Loose JSON-LD / JSON value for extensibility. */
export type JsonLdValue =
  | string
  | number
  | boolean
  | null
  | JsonLdValue[]
  | { [key: string]: JsonLdValue };

/**
 * Base JSON-LD object with optional @context.
 * VC 2.0 allows terms to be carried without @context on nested nodes when inherited.
 */
export interface JsonLdObject {
  '@context'?: JsonLdContext;
  id?: string;
  type?: string | string[];
  [key: string]: JsonLdValue | JsonLdContext | undefined;
}

/** URI string identifying a resource (issuer, schema, status list, etc.). */
export type UriString = string;

/**
 * VC 2.0: `issuer` may be a URI or an object containing an `id` and issuer metadata.
 */
export type Issuer = UriString | IssuerObject;

export interface IssuerObject extends JsonLdObject {
  id: UriString;
}

/** Credential schema reference (VcSchema / credentialSchema). */
export interface CredentialSchemaReference extends JsonLdObject {
  id: UriString;
  type?: string | string[];
}

/** Evidence attached to a credential. */
export interface Evidence extends JsonLdObject {
  id?: UriString;
  type?: string | string[];
}

/** Terms of use for a credential. */
export interface TermsOfUse extends JsonLdObject {
  id?: UriString;
  type?: string | string[];
}

/** Related resource (VC 2.0 related resource pattern). */
export interface RelatedResource extends JsonLdObject {
  id?: UriString;
  type?: string | string[];
}

/**
 * Data Integrity proof (VC 2.0 uses Data Integrity; JWT proofs are separate profile).
 * Aligned with Data Integrity spec proof purpose and crypto suites.
 */
export interface DataIntegrityProof extends JsonLdObject {
  type: string | string[];
  proofPurpose?: string;
  verificationMethod?: UriString;
  created?: string;
  domain?: string;
  challenge?: string;
  proofValue?: string;
  cryptosuite?: string;
  /** Additional suite-specific fields */
  [key: string]: JsonLdValue | JsonLdContext | undefined;
}

/**
 * Verifiable Credential 2.0 core shape.
 * `proof` may be a single proof or an array when multiple proofs exist.
 */
export interface VerifiableCredential<TSubject extends JsonLdObject = JsonLdObject> extends JsonLdObject {
  '@context': JsonLdContext;
  id?: UriString;
  type: string | string[];
  issuer: Issuer;
  validFrom?: string;
  validUntil?: string;
  /** VC 1.x / transitional: issuanceDate */
  issuanceDate?: string;
  /** VC 1.x / transitional: expirationDate */
  expirationDate?: string;
  credentialSubject: TSubject | TSubject[];
  credentialStatus?: CredentialStatus | CredentialStatus[];
  credentialSchema?: CredentialSchemaReference | CredentialSchemaReference[];
  evidence?: Evidence | Evidence[];
  termsOfUse?: TermsOfUse | TermsOfUse[];
  relatedResource?: RelatedResource | RelatedResource[];
  proof?: DataIntegrityProof | DataIntegrityProof[];
}

/**
 * I2H2A delegation scope (human-to-agent), carried in credentialSubject.
 */
export interface I2H2ADelegationScope extends JsonLdObject {
  mcpServers: string[];
  taskType: string;
}

/**
 * I2H2A credentialSubject: agent identity, delegation scope, depth, optional parent chain.
 */
export interface I2H2ACredentialSubject extends JsonLdObject {
  id: UriString;
  scope: I2H2ADelegationScope;
  authorization: Record<string, unknown> | null;
  delegatedBy: string;
  delegationDepth: number;
  parentCredential: UriString | null;
}

/**
 * I2H2A Verifiable Credential (VC 2.0 + I2H2A credential types).
 */
export interface I2H2ACredential extends VerifiableCredential<I2H2ACredentialSubject> {
  type: string | string[];
}

/**
 * Verifiable Presentation 2.0 (holder, optional domain/challenge, embedded credentials, proof).
 */
export interface PresentationObject extends JsonLdObject {
  '@context': JsonLdContext;
  id?: UriString;
  type: string | string[];
  holder: UriString;
  verifiableCredential: I2H2ACredential[] | I2H2ACredential;
  /** OID4VP / request binding */
  domain?: string;
  challenge?: string;
  proof?: DataIntegrityProof | DataIntegrityProof[];
}

/** Primary verification input is SD-JWT+KB compact serialisation string. */
export type PresentationInput = string;

/** W3C DID Core verification method. */
export interface VerificationMethod extends JsonLdObject {
  id: UriString;
  type: string | string[];
  controller: UriString;
  publicKeyJwk?: Record<string, unknown>;
  publicKeyMultibase?: string;
  blockchainAccountId?: string;
}

/** Service endpoint in a DID document. */
export interface Service extends JsonLdObject {
  id: UriString;
  type: string | string[];
  serviceEndpoint: string | string[] | Record<string, unknown>;
}

/**
 * W3C DID Document (subset used for verification).
 */
export interface DIDDocument extends JsonLdObject {
  id: UriString;
  alsoKnownAs?: UriString | UriString[];
  controller?: UriString | UriString[];
  verificationMethod?: VerificationMethod[];
  assertionMethod?: UriString | VerificationMethod[];
  authentication?: UriString | VerificationMethod[];
  keyAgreement?: UriString | VerificationMethod[];
  capabilityInvocation?: UriString | VerificationMethod[];
  capabilityDelegation?: UriString | VerificationMethod[];
  service?: Service[];
}

/**
 * Generic credentialStatus entry (StatusList2021, BitstringStatusList, or extensibility).
 */
export interface CredentialStatus extends JsonLdObject {
  id: UriString;
  type: string | string[];
  statusPurpose?: string;
  statusListCredential?: UriString;
  statusListIndex?: string | number;
  statusReference?: UriString;
  [key: string]: JsonLdValue | JsonLdContext | undefined;
}

export interface VerificationResult {
  valid: boolean;
  error?: string;
  claims?: Record<string, unknown>;
}

export interface VerifyOptions {
  mcpServerId?: string;
  taskType?: string;
  skipStatusCheck?: boolean;
  resolverUrl?: string;
}
