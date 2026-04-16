import jwt, { type JwtHeader } from 'jsonwebtoken';
import { checkCredentialStatus } from './check-status';
import { resolveDidDocument } from './resolve-did';
import type {
  I2H2ACredential,
  I2H2ACredentialSubject,
  JsonLdObject,
  VerifiablePresentation,
  VerifiablePresentationInput,
  VerificationResult,
  VerifyOptions,
} from './types';
import { validateDelegationScope } from './validate-scope';
import {
  credentialTypes,
  credentialValidityWindow,
  decodeJwtVc,
  detectCredentialFormat,
  ensureVerifiableCredentialArray,
  extractIssuerDid,
  extractVpPayloadFromJwt,
  findVerificationMethod,
  firstProof,
  hasI2H2AType,
  isJwtPresentation,
  parseDidAndFragment,
  pickSigningJwk,
  publicKeyFromJwk,
  stripProof,
  verifyDataIntegrityEd25519,
  verifyJwtWithKey,
} from './verify-helpers';

function firstCredentialSubject(cred: I2H2ACredential): I2H2ACredentialSubject {
  const cs = cred.credentialSubject;
  if (Array.isArray(cs)) {
    return cs[0] as I2H2ACredentialSubject;
  }
  return cs as I2H2ACredentialSubject;
}

async function verifyJsonLdVpProof(
  vp: VerifiablePresentation,
  resolverUrl?: string
): Promise<void> {
  const proof = firstProof(vp.proof);
  if (!proof?.verificationMethod) {
    throw new Error('VP must have proof object with verificationMethod');
  }

  const vm = proof.verificationMethod;
  const { did: signerDid } = parseDidAndFragment(vm);
  const agentDoc = await resolveDidDocument(signerDid, resolverUrl);
  const jwk = findVerificationMethod(agentDoc, vm) ?? pickSigningJwk(agentDoc, signerDid, undefined);
  verifyDataIntegrityEd25519(stripProof(vp) as JsonLdObject, proof, jwk);
}

async function verifyJwtVpSignature(
  token: string,
  resolverUrl?: string
): Promise<{ vpPayload: Record<string, unknown>; jwtPayload: jwt.JwtPayload }> {
  const decoded = jwt.decode(token, { complete: true });
  if (!decoded || typeof decoded !== 'object' || !('payload' in decoded)) {
    throw new Error('Invalid JWT VP');
  }
  const payload = decoded.payload as jwt.JwtPayload;
  const header = decoded.header as JwtHeader;
  const iss = payload.iss;
  if (!iss || typeof iss !== 'string') {
    throw new Error('JWT VP must include iss (signer DID)');
  }

  const { did: issuerDid } = parseDidAndFragment(iss);
  const issuerDoc = await resolveDidDocument(issuerDid, resolverUrl);
  const kid = header.kid;
  const jwk = pickSigningJwk(issuerDoc, issuerDid, typeof kid === 'string' ? kid : undefined);
  verifyJwtWithKey(token, publicKeyFromJwk(jwk));

  const vpPayload = extractVpPayloadFromJwt(payload);
  return { vpPayload, jwtPayload: payload };
}

async function verifyI2H2ACredentialSignature(
  raw: unknown,
  resolverUrl?: string
): Promise<{ credential: I2H2ACredential; jwtEnvelope?: jwt.JwtPayload }> {
  if (detectCredentialFormat(raw) === 'jwt') {
    const token = raw as string;
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded || typeof decoded !== 'object' || !('payload' in decoded)) {
      throw new Error('Invalid credential JWT');
    }
    const payload = decoded.payload as jwt.JwtPayload;
    const header = decoded.header as JwtHeader;
    const iss = payload.iss;
    if (!iss || typeof iss !== 'string') {
      throw new Error('Credential JWT must include iss (holder DID)');
    }

    const { did: holderDid } = parseDidAndFragment(iss);
    const holderDoc = await resolveDidDocument(holderDid, resolverUrl);
    const kid = header.kid;
    const jwk = pickSigningJwk(holderDoc, holderDid, typeof kid === 'string' ? kid : undefined);
    verifyJwtWithKey(token, publicKeyFromJwk(jwk));

    const credential = decodeJwtVc(token);
    return { credential, jwtEnvelope: payload };
  }

  const cred = raw as I2H2ACredential;
  const proof = firstProof(cred.proof);
  if (!proof?.verificationMethod) {
    throw new Error('JSON-LD credential must include proof with verificationMethod');
  }

  const issuerDid = extractIssuerDid(cred);
  const { did: issuerBase } = parseDidAndFragment(issuerDid);
  const issuerDoc = await resolveDidDocument(issuerBase, resolverUrl);
  const jwk = findVerificationMethod(issuerDoc, proof.verificationMethod);
  if (!jwk) {
    throw new Error('Could not resolve issuer verification method for credential');
  }

  verifyDataIntegrityEd25519(stripProof(cred) as JsonLdObject, proof, jwk);
  return { credential: cred };
}

function checkCredentialExpiry(
  credential: I2H2ACredential,
  jwtEnvelope?: jwt.JwtPayload
): VerificationResult | null {
  const { start, end } = credentialValidityWindow(credential, jwtEnvelope);
  const now = Date.now();

  if (start != null && now < start) {
    return { valid: false, error: 'I2H2A credential not yet valid' };
  }
  if (end != null && now > end) {
    return { valid: false, error: 'I2H2A credential expired' };
  }
  return null;
}

function validateV1Rules(credential: I2H2ACredential): VerificationResult | null {
  const subject = firstCredentialSubject(credential);
  if (subject.authorization == null) {
    return { valid: false, error: 'credentialSubject.authorization is required' };
  }
  if (typeof subject.delegatedBy !== 'string' || subject.delegatedBy.trim() === '') {
    return { valid: false, error: 'credentialSubject.delegatedBy is required' };
  }
  if (subject.delegationDepth !== 0) {
    return { valid: false, error: 'Invalid delegation depth (must be 0 for V1)' };
  }
  if (subject.parentCredential != null) {
    return { valid: false, error: 'Parent credential must be null for H2A (V1)' };
  }
  return null;
}

function buildClaims(
  credential: I2H2ACredential,
  vpHolder: string,
  credentialIssuerDid: string
): Record<string, unknown> {
  const subject = firstCredentialSubject(credential);
  return {
    agentDid: vpHolder || subject.id,
    holderDid: credentialIssuerDid,
    scope: subject.scope,
    authorization: subject.authorization,
  };
}

/**
 * Verify an I2H2A Verifiable Presentation (OID4VP-style delivery).
 * Supports JSON-LD and compact JWT VPs; JWT and JSON-LD credentials.
 */
export async function verifyI2H2AVP(
  vpInput: VerifiablePresentationInput,
  options?: VerifyOptions
): Promise<VerificationResult> {
  let vpPayload: Record<string, unknown>;
  let vpHolder: string;

  if (isJwtPresentation(vpInput)) {
    try {
      const { vpPayload: inner } = await verifyJwtVpSignature(vpInput, options?.resolverUrl);
      vpPayload = inner;
    } catch {
      return { valid: false, error: 'VP signature verification failed' };
    }

    const holder = vpPayload.holder;
    if (!holder || typeof holder !== 'string') {
      return { valid: false, error: 'VP payload must include holder (DID string)' };
    }
    vpHolder = holder;
  } else {
    const vp = vpInput as VerifiablePresentation;
    if (!vp || typeof vp !== 'object') {
      return { valid: false, error: 'Invalid Verifiable Presentation: expected object or JWT string' };
    }

    const types = vp.type;
    const typeArr = Array.isArray(types) ? types : types != null ? [types] : [];
    if (!typeArr.includes('VerifiablePresentation')) {
      return { valid: false, error: 'VP must include type VerifiablePresentation' };
    }

    if (!vp.holder || typeof vp.holder !== 'string') {
      return { valid: false, error: 'VP must include holder (DID string)' };
    }

    try {
      await verifyJsonLdVpProof(vp, options?.resolverUrl);
    } catch {
      return { valid: false, error: 'VP signature verification failed' };
    }

    vpPayload = vp as unknown as Record<string, unknown>;
    vpHolder = vp.holder;
  }

  const vcArray = ensureVerifiableCredentialArray(vpPayload);
  if (!vcArray) {
    return { valid: false, error: 'VP must contain verifiableCredential array' };
  }

  let rawI2H2A: unknown;
  for (const item of vcArray) {
    if (hasI2H2AType(item)) {
      rawI2H2A = item;
      break;
    }
  }
  if (rawI2H2A === undefined) {
    return { valid: false, error: 'No I2H2A credential in VP' };
  }

  let credential: I2H2ACredential;
  let credJwtEnv: jwt.JwtPayload | undefined;

  try {
    const out = await verifyI2H2ACredentialSignature(rawI2H2A, options?.resolverUrl);
    credential = out.credential;
    credJwtEnv = out.jwtEnvelope;
  } catch (e) {
    if (e instanceof jwt.TokenExpiredError) {
      return { valid: false, error: 'I2H2A credential expired' };
    }
    if (e instanceof jwt.NotBeforeError) {
      return { valid: false, error: 'I2H2A credential not yet valid' };
    }
    return { valid: false, error: 'I2H2A credential signature verification failed' };
  }

  const expiryErr = checkCredentialExpiry(credential, credJwtEnv);
  if (expiryErr) {
    return expiryErr;
  }

  if (!options?.skipStatusCheck) {
    try {
      const ok = await checkCredentialStatus(credential);
      if (!ok) {
        return { valid: false, error: 'I2H2A credential revoked' };
      }
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return { valid: false, error: `Status check failed: ${msg}` };
    }
  }

  const scopeRequested =
    (options?.mcpServerId !== undefined && options.mcpServerId !== '') ||
    (options?.taskType !== undefined && options.taskType !== '');
  if (scopeRequested) {
    const mid = options?.mcpServerId ?? '';
    const tt = options?.taskType ?? '';
    if (!mid || !tt) {
      return {
        valid: false,
        error: 'Delegation scope validation requires both mcpServerId and taskType',
      };
    }
    if (!validateDelegationScope(credential, mid, tt)) {
      return { valid: false, error: 'Delegation scope does not match request' };
    }
  }

  const v1 = validateV1Rules(credential);
  if (v1) {
    return v1;
  }

  const credentialIssuerDid = typeof credJwtEnv?.iss === 'string' ? credJwtEnv.iss : '';
  return { valid: true, claims: buildClaims(credential, vpHolder, credentialIssuerDid) };
}
