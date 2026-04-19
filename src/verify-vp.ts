import * as crypto from 'crypto';
import { checkCredentialStatus } from './check-status';
import { resolveDidDocument } from './resolve-did';
import type {
  I2H2ADisclosedClaims,
  I2H2AIssuerPayload,
  KbJwtPayload,
  P256Jwk,
  VerificationResult,
  VerifyOptions,
} from './types';
import { validateDelegationScope } from './validate-scope';
import {
  b64urlDecode,
  decodeDisclosure,
  decodeJwtPart,
  parseSdJwtKb,
  sha256Base64url,
  splitJwt,
  verifyEs256Signature,
} from './verify-helpers';

function safeEqualString(a: string, b: string): boolean {
  const aBuf = Buffer.from(a, 'utf8');
  const bBuf = Buffer.from(b, 'utf8');
  if (aBuf.length !== bBuf.length) {
    return false;
  }
  return crypto.timingSafeEqual(aBuf, bBuf);
}

export async function verifyI2H2APresentation(
  token: string,
  options: VerifyOptions
): Promise<VerificationResult> {
  let issuerJwt: string;
  let disclosures: string[];
  let kbJwt: string;
  try {
    const parsed = parseSdJwtKb(token);
    issuerJwt = parsed.issuerJwt;
    disclosures = parsed.disclosures;
    kbJwt = parsed.kbJwt;
  } catch {
    return { valid: false, error: 'Invalid SD-JWT+KB format' };
  }

  const issuerParts = splitJwt(issuerJwt);
  if (!issuerParts) {
    return { valid: false, error: 'Invalid issuer JWT' };
  }
  const [issuerHeaderB64, issuerPayloadB64] = issuerParts;
  const issuerHeader = decodeJwtPart(issuerHeaderB64);
  if (issuerHeader == null || typeof issuerHeader !== 'object') {
    return { valid: false, error: 'Invalid issuer JWT header' };
  }
  const issuerPayload = decodeJwtPart(issuerPayloadB64) as I2H2AIssuerPayload;

  if (issuerPayload.vct !== 'I2H2A') {
    return { valid: false, error: 'Invalid vct (expected I2H2A)' };
  }
  if (issuerPayload._sd_alg !== 'sha-256') {
    return { valid: false, error: 'Invalid _sd_alg (expected sha-256)' };
  }

  let issuerDidDoc;
  try {
    issuerDidDoc = await resolveDidDocument(issuerPayload.iss, options.resolverUrl);
  } catch {
    return { valid: false, error: 'Issuer DID resolution failed' };
  }

  let issuerJwk: P256Jwk | null = null;
  for (const vm of issuerDidDoc.verificationMethod ?? []) {
    const maybeJwk = vm.publicKeyJwk;
    if (
      maybeJwk &&
      typeof maybeJwk === 'object' &&
      maybeJwk.crv === 'P-256' &&
      maybeJwk.kty === 'EC' &&
      typeof maybeJwk.x === 'string' &&
      typeof maybeJwk.y === 'string'
    ) {
      issuerJwk = maybeJwk as P256Jwk;
      break;
    }
  }
  if (!issuerJwk) {
    return { valid: false, error: 'No P-256 key in issuer DID document' };
  }

  if (!verifyEs256Signature(issuerJwt, issuerJwk)) {
    return { valid: false, error: 'Issuer JWT signature invalid' };
  }

  const now = Math.floor(Date.now() / 1000);
  if (issuerPayload.nbf != null && issuerPayload.nbf > now) {
    return { valid: false, error: 'Issuer JWT not yet valid' };
  }
  if (issuerPayload.exp <= now) {
    return { valid: false, error: 'Issuer JWT expired' };
  }

  for (const disclosure of disclosures) {
    try {
      b64urlDecode(disclosure);
    } catch {
      return { valid: false, error: 'Invalid disclosure encoding' };
    }
    const digest = sha256Base64url(disclosure);
    if (!issuerPayload._sd.includes(digest)) {
      return { valid: false, error: 'Disclosure hash mismatch' };
    }
  }

  const claims: I2H2ADisclosedClaims = {};
  for (const disclosure of disclosures) {
    const tuple = decodeDisclosure(disclosure) as [unknown, unknown, unknown];
    const key = tuple[1];
    if (typeof key !== 'string' || key.length === 0) {
      return { valid: false, error: 'Invalid disclosure claim key' };
    }
    const value = tuple[2];
    (claims as Record<string, unknown>)[key] = value;
  }

  const sdInput = `${issuerJwt}~${disclosures.join('~')}~`;
  const sdHash = sha256Base64url(sdInput);

  const kbParts = splitJwt(kbJwt);
  if (!kbParts) {
    return { valid: false, error: 'Invalid KB-JWT' };
  }
  const [, kbPayloadB64] = kbParts;
  const kbPayload = decodeJwtPart(kbPayloadB64) as KbJwtPayload;
  if (!safeEqualString(kbPayload.aud, options.mcpServerId)) {
    return { valid: false, error: 'KB-JWT aud mismatch' };
  }
  if (!safeEqualString(kbPayload.nonce, options.nonce)) {
    return { valid: false, error: 'KB-JWT nonce mismatch' };
  }
  if (!safeEqualString(kbPayload.sd_hash, sdHash)) {
    return { valid: false, error: 'KB-JWT sd_hash mismatch' };
  }

  const holderJwk = issuerPayload.cnf.jwk;
  if (
    !holderJwk ||
    holderJwk.kty !== 'EC' ||
    holderJwk.crv !== 'P-256' ||
    typeof holderJwk.x !== 'string' ||
    typeof holderJwk.y !== 'string'
  ) {
    return { valid: false, error: 'Invalid holder key in cnf.jwk' };
  }
  if (!verifyEs256Signature(kbJwt, holderJwk)) {
    return { valid: false, error: 'KB-JWT signature invalid' };
  }

  if (!options.skipStatusCheck && issuerPayload.credentialStatus) {
    try {
      const isActive = await checkCredentialStatus(issuerPayload.credentialStatus);
      if (!isActive) {
        return { valid: false, error: 'Credential revoked' };
      }
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return { valid: false, error: `Status check failed: ${msg}` };
    }
  }

  if (claims.delegationDepth !== 0) {
    return { valid: false, error: 'Invalid delegation depth (must be 0 for V1)' };
  }
  if (claims.parentCredential !== null && claims.parentCredential !== undefined) {
    return { valid: false, error: 'Parent credential must be null for H2A (V1)' };
  }
  if (typeof claims.delegatedBy !== 'string' || claims.delegatedBy.trim() === '') {
    return { valid: false, error: 'delegatedBy is required' };
  }

  if (!validateDelegationScope(claims, options.mcpServerId)) {
    return { valid: false, error: 'Delegation scope does not permit this MCP server' };
  }

  return {
    valid: true,
    claims: {
      agentDid: issuerPayload.sub,
      delegatedBy: claims.delegatedBy as string,
      scope: {
        mcpServers: (claims['scope.mcpServers'] ?? []) as string[],
        taskType: (claims['scope.taskType'] ?? '') as string,
      },
      authorization: claims.authorization ?? null,
    },
  };
}
