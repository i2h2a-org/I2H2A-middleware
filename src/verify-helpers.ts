import * as crypto from 'crypto';
import jwt from 'jsonwebtoken';
import type {
  DataIntegrityProof,
  DIDDocument,
  I2H2ACredential,
  JsonLdObject,
  VerificationMethod,
} from './types';

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function detectCredentialFormat(credential: unknown): 'jwt' | 'jsonld' {
  if (typeof credential === 'string' && credential.startsWith('eyJ')) {
    return 'jwt';
  }
  return 'jsonld';
}

/** True if `obj.type` includes I2H2A (VC or nested VC object). */
function recordHasI2H2AType(obj: Record<string, unknown>): boolean {
  const t = obj.type;
  const arr = Array.isArray(t) ? t.map(String) : typeof t === 'string' ? [t] : [];
  if (arr.includes('I2H2A')) {
    return true;
  }
  const cs = obj.credentialSubject;
  const sub = Array.isArray(cs) ? cs[0] : cs;
  if (sub && typeof sub === 'object' && !Array.isArray(sub)) {
    return recordHasI2H2AType(sub as Record<string, unknown>);
  }
  return false;
}

/**
 * Some issuers (e.g. cheqd Studio) wrap claims as VC-in-credentialSubject; unwrap to a flat I2H2A shape.
 */
function jwtPayloadToI2H2ACredential(decoded: Record<string, unknown>): I2H2ACredential {
  const rootVc = decoded.vc;
  const vcRoot =
    rootVc && typeof rootVc === 'object' ? (rootVc as Record<string, unknown>) : decoded;

  let node: Record<string, unknown> = vcRoot;
  for (let depth = 0; depth < 6; depth++) {
    const types = credentialTypes(node as I2H2ACredential);
    if (types.includes('I2H2A')) {
      let leaf = node.credentialSubject;
      if (Array.isArray(leaf)) {
        leaf = leaf[0];
      }
      while (
        leaf &&
        typeof leaf === 'object' &&
        !Array.isArray(leaf) &&
        (leaf as Record<string, unknown>).credentialSubject != null &&
        (leaf as Record<string, unknown>).scope == null
      ) {
        const inner = (leaf as Record<string, unknown>).credentialSubject;
        leaf = Array.isArray(inner) ? inner[0] : inner;
      }

      const iss = decoded.iss;
      const out = {
        ...node,
        issuer: typeof iss === 'string' ? iss : node.issuer,
        credentialSubject: leaf,
      } as I2H2ACredential;
      return out;
    }

    const cs = node.credentialSubject;
    const next = Array.isArray(cs) ? cs[0] : cs;
    if (!next || typeof next !== 'object' || Array.isArray(next)) {
      break;
    }
    node = next as Record<string, unknown>;
  }

  throw new Error('JWT payload has no I2H2A-typed verifiable credential');
}

export function decodeJwtVc(jwtStr: string): I2H2ACredential {
  const decoded = jwt.decode(jwtStr, { complete: false }) as Record<string, unknown> | null;
  if (!decoded || typeof decoded !== 'object') {
    throw new Error('Invalid JWT: could not decode payload');
  }
  return jwtPayloadToI2H2ACredential(decoded);
}

export function firstProof(
  proof: DataIntegrityProof | DataIntegrityProof[] | undefined
): DataIntegrityProof | undefined {
  if (!proof) return undefined;
  return Array.isArray(proof) ? proof[0] : proof;
}

/** Deterministic JSON serialization (JCS-style: sorted keys, no extra whitespace). */
export function jcsCanonicalize(value: unknown): string {
  return JSON.stringify(canonicalizeValue(value));
}

function canonicalizeValue(value: unknown): unknown {
  if (value === null || typeof value !== 'object') {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((v) => canonicalizeValue(v));
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  const out: Record<string, unknown> = {};
  for (const k of keys) {
    out[k] = canonicalizeValue(obj[k]);
  }
  return out;
}

export function stripProof<T extends JsonLdObject>(doc: T): Omit<T, 'proof'> {
  const copy = { ...doc } as T & { proof?: unknown };
  delete copy.proof;
  return copy as Omit<T, 'proof'>;
}

/** Multibase base58-btc (`z` prefix) → raw bytes. */
export function decodeMultibaseZ(multibase: string): Buffer {
  if (!multibase.startsWith('z')) {
    throw new Error('Expected multibase z (base58-btc) encoded value');
  }
  return decodeBase58Btc(multibase.slice(1));
}

function decodeBase58Btc(str: string): Buffer {
  let num = 0n;
  for (const c of str) {
    const idx = BASE58_ALPHABET.indexOf(c);
    if (idx < 0) {
      throw new Error('Invalid base58 character');
    }
    num = num * 58n + BigInt(idx);
  }
  let hex = num.toString(16);
  if (hex.length % 2) {
    hex = `0${hex}`;
  }
  const buf = Buffer.from(hex, 'hex');
  let leading = 0;
  for (let i = 0; i < str.length && str[i] === '1'; i++) {
    leading++;
  }
  return Buffer.concat([Buffer.alloc(leading), buf]);
}

export function parseDidAndFragment(vm: string): { did: string; fragment?: string } {
  const hash = vm.indexOf('#');
  if (hash < 0) {
    return { did: vm };
  }
  return { did: vm.slice(0, hash), fragment: vm.slice(hash + 1) };
}

/** P-256 `publicKeyMultibase` (z + base58btc) → JWK. */
export function jwkFromP256PublicKeyMultibase(multibase: string): crypto.JsonWebKey {
  const multicodecBytes = decodeMultibaseZ(multibase);
  if (multicodecBytes.length < 3 || multicodecBytes[0] !== 0xed || multicodecBytes[1] !== 0x01) {
    throw new Error('Only P-256 multibase public keys are supported');
  }
  const publicKeyBytes = multicodecBytes.subarray(2);
  if (publicKeyBytes.length !== 32) {
    throw new Error(`Invalid P-256 public key length: ${publicKeyBytes.length}`);
  }
  return {
    kty: 'EC',
    crv: 'P-256',
    x: Buffer.from(publicKeyBytes).toString('base64url'),
  };
}

export function jwkFromVerificationMethod(vm: VerificationMethod): crypto.JsonWebKey | null {
  if (vm.publicKeyJwk && typeof vm.publicKeyJwk === 'object') {
    return vm.publicKeyJwk as crypto.JsonWebKey;
  }
  const multibase = vm.publicKeyMultibase;
  if (typeof multibase !== 'string') {
    return null;
  }
  const types = Array.isArray(vm.type) ? vm.type : [vm.type];
  const p256 = types.some(
    (t) => typeof t === 'string' && (t.includes('P-256') || t === 'Multikey')
  );
  if (!p256) {
    return null;
  }
  try {
    return jwkFromP256PublicKeyMultibase(multibase);
  } catch {
    return null;
  }
}

export function findVerificationMethod(
  didDoc: DIDDocument,
  verificationMethodId: string
): crypto.JsonWebKey | null {
  const { fragment } = parseDidAndFragment(verificationMethodId);
  const methods = didDoc.verificationMethod ?? [];

  for (const vm of methods) {
    if (!vm.id) continue;
    const idMatch =
      vm.id === verificationMethodId ||
      (fragment != null && vm.id.endsWith(`#${fragment}`));
    if (idMatch) {
      return jwkFromVerificationMethod(vm);
    }
  }

  return null;
}

export function pickSigningJwk(didDoc: DIDDocument, issDid: string, kid?: string): crypto.JsonWebKey {
  if (kid) {
    const vmId = kid.startsWith('did:') ? kid : `${issDid}#${kid}`;
    const jwk = findVerificationMethod(didDoc, vmId);
    if (jwk) {
      return jwk;
    }
  }
  for (const vm of didDoc.verificationMethod ?? []) {
    const jwk = jwkFromVerificationMethod(vm);
    if (jwk) {
      return jwk;
    }
  }
  throw new Error('No public key found in DID document for signature verification');
}

export function publicKeyFromJwk(jwk: crypto.JsonWebKey): crypto.KeyObject {
  return crypto.createPublicKey({ key: jwk, format: 'jwk' });
}

/**
 * RS/ES/PS algorithms use `jsonwebtoken` → `jws` → `jwa`.
 * ES256 verification path uses Node crypto.
 */
const JWT_VERIFY_OPTIONS: jwt.VerifyOptions = {
  algorithms: ['RS256', 'ES256'] as jwt.Algorithm[],
  allowInvalidAsymmetricKeyTypes: true,
};

function verifyEs256JwtWithNodeCrypto(token: string, publicKey: crypto.KeyObject): jwt.JwtPayload {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new jwt.JsonWebTokenError('jwt malformed');
  }

  const securedInput = `${parts[0]}.${parts[1]}`;
  const signingInput = Buffer.from(securedInput, 'utf8');
  let sigBuf: Buffer;
  try {
    sigBuf = Buffer.from(parts[2], 'base64url');
  } catch {
    throw new jwt.JsonWebTokenError('invalid signature');
  }

  const ok = crypto.verify(null, signingInput, publicKey, sigBuf);
  if (!ok) {
    throw new jwt.JsonWebTokenError('invalid signature');
  }

  let payload: jwt.JwtPayload;
  try {
    payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')) as jwt.JwtPayload;
  } catch {
    throw new jwt.JsonWebTokenError('invalid payload');
  }

  const clockTimestamp = Math.floor(Date.now() / 1000);
  if (payload.nbf !== undefined && typeof payload.nbf === 'number') {
    if (clockTimestamp < payload.nbf) {
      throw new jwt.NotBeforeError('jwt not active', new Date(payload.nbf * 1000));
    }
  }
  if (payload.exp !== undefined && typeof payload.exp === 'number') {
    if (clockTimestamp >= payload.exp) {
      throw new jwt.TokenExpiredError('jwt expired', new Date(payload.exp * 1000));
    }
  }

  return payload;
}

export function verifyJwtWithKey(token: string, publicKey: crypto.KeyObject): jwt.JwtPayload {
  const complete = jwt.decode(token, { complete: true });
  const alg = complete?.header && typeof complete.header === 'object' ? complete.header.alg : undefined;

  if (alg === 'ES256') {
    return verifyEs256JwtWithNodeCrypto(token, publicKey);
  }

  return jwt.verify(token, publicKey, JWT_VERIFY_OPTIONS) as jwt.JwtPayload;
}

export function verifyDataIntegrityEs256(
  documentWithoutProof: JsonLdObject,
  proof: DataIntegrityProof,
  publicKeyJwk: crypto.JsonWebKey
): void {
  const proofValue = proof.proofValue;
  if (!proofValue || typeof proofValue !== 'string') {
    throw new Error('proofValue is required for Data Integrity verification');
  }

  const msg = Buffer.from(jcsCanonicalize(documentWithoutProof), 'utf8');
  const sig = decodeMultibaseZ(proofValue);
  const key = publicKeyFromJwk(publicKeyJwk);

  const ok = crypto.verify(null, msg, key, sig);
  if (!ok) {
    throw new Error('Data Integrity signature verification failed');
  }
}

export function extractIssuerDid(credential: I2H2ACredential): string {
  const iss = credential.issuer;
  if (typeof iss === 'string') {
    return iss;
  }
  if (iss && typeof iss === 'object' && 'id' in iss && typeof (iss as { id: unknown }).id === 'string') {
    return (iss as { id: string }).id;
  }
  throw new Error('Credential issuer must be a DID string or object with id');
}

export function credentialTypes(credential: I2H2ACredential): string[] {
  const t = credential.type;
  if (Array.isArray(t)) return t.map(String);
  if (typeof t === 'string') return [t];
  return [];
}

export function hasI2H2AType(credential: unknown): boolean {
  if (detectCredentialFormat(credential) === 'jwt') {
    try {
      const decoded = jwt.decode(credential as string, { complete: false }) as Record<string, unknown> | null;
      if (!decoded || typeof decoded !== 'object') {
        return false;
      }
      const rootVc = decoded.vc;
      const vcRoot =
        rootVc && typeof rootVc === 'object' ? (rootVc as Record<string, unknown>) : decoded;
      return recordHasI2H2AType(vcRoot);
    } catch {
      return false;
    }
  }
  const c = credential as I2H2ACredential;
  if (credentialTypes(c).includes('I2H2A')) {
    return true;
  }
  return recordHasI2H2AType(c as unknown as Record<string, unknown>);
}

export function extractVpPayloadFromJwt(jwtPayload: jwt.JwtPayload): Record<string, unknown> {
  const p = jwtPayload as Record<string, unknown>;
  if (p.vp && typeof p.vp === 'object') {
    return p.vp as Record<string, unknown>;
  }
  return p;
}

export function ensureVerifiableCredentialArray(vp: Record<string, unknown>): unknown[] | null {
  const vcs = vp.verifiableCredential;
  if (!Array.isArray(vcs)) {
    return null;
  }
  return vcs;
}

export function parseIsoDate(value: string | undefined): number | undefined {
  if (!value) return undefined;
  const t = Date.parse(value);
  return Number.isNaN(t) ? undefined : t;
}

export interface TimeWindow {
  start?: number;
  end?: number;
}

export function credentialValidityWindow(
  cred: I2H2ACredential,
  jwtEnvelope?: jwt.JwtPayload
): TimeWindow {
  const start =
    parseIsoDate(cred.validFrom) ??
    parseIsoDate(cred.issuanceDate) ??
    (jwtEnvelope?.nbf != null ? jwtEnvelope.nbf * 1000 : undefined) ??
    (jwtEnvelope?.iat != null ? jwtEnvelope.iat * 1000 : undefined);

  const end =
    parseIsoDate(cred.validUntil) ??
    parseIsoDate(cred.expirationDate) ??
    (jwtEnvelope?.exp != null ? jwtEnvelope.exp * 1000 : undefined);

  return { start, end };
}

export function isJwtPresentation(vp: unknown): vp is string {
  return typeof vp === 'string' && vp.startsWith('eyJ');
}
