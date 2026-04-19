import * as crypto from 'crypto';
import type { P256Jwk } from './types';

export function b64urlDecode(str: string): Buffer {
  const b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padded = b64 + '=='.slice(0, (4 - (b64.length % 4)) % 4);
  return Buffer.from(padded, 'base64');
}

export function b64urlEncode(buf: Buffer | Uint8Array): string {
  return Buffer.from(buf).toString('base64url');
}

export function decodeJwtPart(part: string): unknown {
  return JSON.parse(b64urlDecode(part).toString('utf8'));
}

export function splitJwt(token: string): [string, string, string] {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error(`Invalid JWT: expected 3 parts, got ${parts.length}`);
  return [parts[0] as string, parts[1] as string, parts[2] as string];
}

export function verifyEs256Signature(token: string, jwk: P256Jwk): boolean {
  const [headerB64, payloadB64, sigB64] = splitJwt(token);
  const signingInput = Buffer.from(`${headerB64}.${payloadB64}`, 'utf8');
  const sigBytes = b64urlDecode(sigB64);
  let publicKey: crypto.KeyObject;
  try {
    publicKey = crypto.createPublicKey({ key: jwk as unknown as crypto.JsonWebKey, format: 'jwk' });
  } catch {
    throw new Error('Failed to import P-256 public key from JWK');
  }
  try {
    const derSig = rawEcdsaToDer(sigBytes);
    return crypto.verify('SHA256', signingInput, publicKey, derSig);
  } catch {
    return false;
  }
}

function rawEcdsaToDer(raw: Buffer): Buffer {
  if (raw.length !== 64) throw new Error(`Expected 64-byte raw ECDSA signature, got ${raw.length}`);
  const r = raw.subarray(0, 32);
  const s = raw.subarray(32, 64);
  function encodeInt(buf: Buffer): Buffer {
    let start = 0;
    while (start < buf.length - 1 && buf[start] === 0) start++;
    const trimmed = buf.subarray(start);
    const needsPad = ((trimmed[0] as number) & 0x80) !== 0;
    const encoded = needsPad ? Buffer.concat([Buffer.from([0x00]), trimmed]) : trimmed;
    return Buffer.concat([Buffer.from([0x02, encoded.length]), encoded]);
  }
  const rDer = encodeInt(Buffer.from(r));
  const sDer = encodeInt(Buffer.from(s));
  const seq = Buffer.concat([rDer, sDer]);
  return Buffer.concat([Buffer.from([0x30, seq.length]), seq]);
}

export function sha256Base64url(input: string): string {
  return crypto.createHash('sha256').update(input, 'utf8').digest('base64url');
}

export function decodeDisclosure(disclosure: string): [string, string, unknown] {
  const decoded = JSON.parse(b64urlDecode(disclosure).toString('utf8')) as unknown[];
  if (!Array.isArray(decoded) || decoded.length !== 3) {
    throw new Error('Invalid disclosure format');
  }
  return [decoded[0] as string, decoded[1] as string, decoded[2]];
}

export function parseSdJwtKb(token: string): { issuerJwt: string; disclosures: string[]; kbJwt: string } {
  const parts = token.split('~');
  if (parts.length < 3) {
    throw new Error('Invalid SD-JWT+KB: expected at least issuerJwt~disclosure~kbJwt');
  }
  return {
    issuerJwt: parts[0] as string,
    disclosures: parts.slice(1, parts.length - 1),
    kbJwt: parts[parts.length - 1] as string,
  };
}
