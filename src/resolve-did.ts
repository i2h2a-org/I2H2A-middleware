import fetch from 'node-fetch';
import type { DIDDocument } from './types';

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const P256_MULTICODEC_PREFIX_0 = 0x80;
const P256_MULTICODEC_PREFIX_1 = 0x24;
const P256_COMPRESSED_POINT_LENGTH = 33;
const UNIVERSAL_RESOLVER_DEFAULT_URL = 'https://dev.uniresolver.io/1.0/identifiers/';

// NIST P-256 field parameters
const P256_P = BigInt('0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff');
const P256_B = BigInt('0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b');

function base58BtcDecode(str: string): Buffer {
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

/**
 * Positive modulo for BigInt arithmetic in finite fields.
 */
function mod(a: bigint, m: bigint): bigint {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  if (modulus === 1n) {
    return 0n;
  }

  let result = 1n;
  let b = mod(base, modulus);
  let e = exponent;

  while (e > 0n) {
    if ((e & 1n) === 1n) {
      result = mod(result * b, modulus);
    }
    b = mod(b * b, modulus);
    e >>= 1n;
  }

  return result;
}

function bigintFromBuffer(buf: Buffer): bigint {
  if (buf.length === 0) {
    return 0n;
  }
  return BigInt(`0x${buf.toString('hex')}`);
}

function bufferFromBigint(value: bigint, size: number): Buffer {
  let hex = value.toString(16);
  const targetHexLength = size * 2;
  if (hex.length > targetHexLength) {
    throw new Error('BigInt does not fit in requested buffer size');
  }
  hex = hex.padStart(targetHexLength, '0');
  return Buffer.from(hex, 'hex');
}

function recoverP256YFromX(x: bigint, odd: boolean): bigint {
  const x2 = mod(x * x, P256_P);
  const x3 = mod(x2 * x, P256_P);
  const ax = mod(-3n * x, P256_P);
  const rhs = mod(x3 + ax + P256_B, P256_P);

  // p mod 4 = 3 for P-256 prime, so sqrt can use rhs^((p+1)/4) mod p.
  const yCandidate = modPow(rhs, (P256_P + 1n) / 4n, P256_P);
  if (mod(yCandidate * yCandidate, P256_P) !== rhs) {
    throw new Error('Invalid compressed P-256 point: not on curve');
  }

  const isOdd = (yCandidate & 1n) === 1n;
  if (isOdd === odd) {
    return yCandidate;
  }
  return mod(P256_P - yCandidate, P256_P);
}

function decodeP256DidKeyToJwk(multicodecBytes: Buffer): {
  x: string;
  y: string;
} {
  if (multicodecBytes.length < 2 + P256_COMPRESSED_POINT_LENGTH) {
    throw new Error('did:key multicodec payload too short for P-256 key');
  }
  if (
    multicodecBytes[0] !== P256_MULTICODEC_PREFIX_0 ||
    multicodecBytes[1] !== P256_MULTICODEC_PREFIX_1
  ) {
    throw new Error('Only P-256 did:key is supported (multicodec 0x1200 / bytes 0x80 0x24)');
  }

  const compressed = multicodecBytes.subarray(2);
  if (compressed.length !== P256_COMPRESSED_POINT_LENGTH) {
    throw new Error(`Invalid P-256 compressed point length: ${compressed.length}`);
  }

  const prefix = compressed[0];
  if (prefix !== 0x02 && prefix !== 0x03) {
    throw new Error('Invalid compressed P-256 point prefix');
  }

  const xBuf = compressed.subarray(1);
  if (xBuf.length !== 32) {
    throw new Error('Invalid P-256 x-coordinate length');
  }

  const x = bigintFromBuffer(xBuf);
  const odd = prefix === 0x03;
  const y = recoverP256YFromX(x, odd);
  const yBuf = bufferFromBigint(y, 32);

  return {
    x: xBuf.toString('base64url'),
    y: yBuf.toString('base64url'),
  };
}

/**
 * Resolve did:key locally without HTTP.
 * Format: did:key:z{base58-btc(multicodec prefix + compressed public key)}.
 * P-256 multicodec varint is 0x1200 => bytes 0x80, 0x24.
 */
function resolveDidKeyLocally(did: string): DIDDocument {
  if (!did.startsWith('did:key:')) {
    throw new Error(`Expected did:key, got: ${did}`);
  }

  const keyPart = did.slice('did:key:'.length);
  if (!keyPart.startsWith('z')) {
    throw new Error('did:key must use base58-btc multibase (z prefix)');
  }

  const multicodecBytes = base58BtcDecode(keyPart.slice(1));
  const jwk = decodeP256DidKeyToJwk(multicodecBytes);
  const verificationMethodId = `${did}#${keyPart}`;

  return {
    id: did,
    verificationMethod: [
      {
        id: verificationMethodId,
        type: 'JsonWebKey2020',
        controller: did,
        publicKeyJwk: {
          kty: 'EC',
          crv: 'P-256',
          x: jwk.x,
          y: jwk.y,
        },
      },
    ],
    authentication: [verificationMethodId],
    assertionMethod: [verificationMethodId],
  };
}

export interface UniversalResolverResponse {
  didDocument?: DIDDocument;
  didResolutionMetadata?: Record<string, unknown>;
  didDocumentMetadata?: Record<string, unknown>;
}

function toUniversalResolverUrl(base: string, did: string): string {
  const normalizedBase = base.endsWith('/') ? base : `${base}/`;
  return `${normalizedBase}${encodeURIComponent(did)}`;
}

async function resolveViaUniversalResolver(did: string, resolverUrl?: string): Promise<DIDDocument> {
  const base = resolverUrl ?? UNIVERSAL_RESOLVER_DEFAULT_URL;
  const url = toUniversalResolverUrl(base, did);
  const res = await fetch(url, {
    headers: { Accept: 'application/did+json,application/json' },
  });

  if (!res.ok) {
    throw new Error(`DID resolution failed (${res.status}): ${did}`);
  }

  const body = (await res.json()) as UniversalResolverResponse;
  if (!body.didDocument || typeof body.didDocument !== 'object') {
    throw new Error(`DID resolution returned no didDocument for ${did}`);
  }

  return body.didDocument;
}

/**
 * Resolve a DID to its DID document (verification methods, etc.).
 * did:key is resolved locally; did:web and did:cheqd are resolved via universal resolver HTTP API.
 */
export async function resolveDidDocument(did: string, resolverUrl?: string): Promise<DIDDocument> {
  if (!did || typeof did !== 'string' || !did.startsWith('did:')) {
    throw new Error(`Invalid DID: ${did}`);
  }

  const fragmentIndex = did.indexOf('#');
  const didWithoutFragment = fragmentIndex >= 0 ? did.slice(0, fragmentIndex) : did;

  if (didWithoutFragment.startsWith('did:key:')) {
    return resolveDidKeyLocally(didWithoutFragment);
  }

  const method = didWithoutFragment.split(':')[1];

  if (!method) {
    throw new Error(`Invalid DID (no method): ${did}`);
  }

  if (method === 'web' || method === 'cheqd') {
    return resolveViaUniversalResolver(didWithoutFragment, resolverUrl);
  }

  throw new Error(`Unsupported DID method for resolver: ${method}`);
}
