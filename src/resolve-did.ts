import {
  Resolver,
  type DIDDocument as DidResolverDocument,
  type DIDResolutionOptions,
  type DIDResolutionResult,
  type DIDResolver,
  type ParsedDID,
  type Resolvable,
} from 'did-resolver';
import fetch from 'node-fetch';
import type { DIDDocument } from './types';

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

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
 * Resolve did:key locally without HTTP.
 * Format: did:key:z{base58-btc(multicodec prefix + raw public key)}.
 * Ed25519: multicodec prefix 0xed 0x01 + 32-byte public key.
 */
function resolveDidKeyLocally(did: string): DIDDocument {
  if (!did.startsWith('did:key:')) {
    throw new Error(`Expected did:key, got: ${did}`);
  }

  const keyPart = did.slice('did:key:'.length);
  if (!keyPart.startsWith('z')) {
    throw new Error('did:key must use base58-btc multibase (z prefix)');
  }

  const base58Payload = keyPart.slice(1);
  const multicodecBytes = base58BtcDecode(base58Payload);

  if (multicodecBytes.length < 3) {
    throw new Error('did:key multicodec payload too short');
  }
  if (multicodecBytes[0] !== 0xed || multicodecBytes[1] !== 0x01) {
    throw new Error('Only Ed25519 did:key is supported (multicodec 0xed01)');
  }

  const publicKeyBytes = multicodecBytes.subarray(2);
  if (publicKeyBytes.length !== 32) {
    throw new Error(`Invalid Ed25519 public key length: ${publicKeyBytes.length}`);
  }

  const verificationMethodId = `${did}#${keyPart}`;

  return {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: did,
    verificationMethod: [
      {
        id: verificationMethodId,
        type: 'Ed25519VerificationKey2020',
        controller: did,
        publicKeyJwk: {
          kty: 'OKP',
          crv: 'Ed25519',
          x: Buffer.from(publicKeyBytes).toString('base64url'),
        },
      },
    ],
    authentication: verificationMethodId,
    assertionMethod: verificationMethodId,
    capabilityDelegation: verificationMethodId,
    capabilityInvocation: verificationMethodId,
  };
}

/** Default public universal resolver (HTTP binding); override in tests or production. */
const DEFAULT_UNIVERSAL_RESOLVER =
  process.env.I2H2A_UNIVERSAL_RESOLVER_URL ?? 'https://dev.uniresolver.io/1.0/identifiers/';

export interface UniversalResolverResponse {
  didDocument?: DidResolverDocument;
  didResolutionMetadata?: Record<string, unknown>;
  didDocumentMetadata?: Record<string, unknown>;
}

async function resolveViaUniversalBinding(did: string): Promise<DidResolverDocument> {
  const url = `${DEFAULT_UNIVERSAL_RESOLVER}${encodeURIComponent(did)}`;
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

/** cheqd hosted driver; works for testnet and mainnet DIDs. */
const CHEQD_RESOLVER_BASE = 'https://resolver.cheqd.net/1.0/identifiers/';

/**
 * TODO: Remove this cheqd-specific resolver before v1.0
 *
 * This is a temporary convenience feature while universal resolvers
 * don't properly support did:cheqd. For true platform-agnosticism,
 * all DID methods (except did:key which is self-resolving) should
 * use a configurable universal resolver endpoint.
 *
 * Options for v1.0:
 * - Remove this and rely on universal resolver
 * - Make resolver endpoint configurable via env var
 * - Implement plugin architecture for custom resolvers
 */
async function resolveCheqdDidDirectly(did: string): Promise<DIDDocument> {
  const url = `${CHEQD_RESOLVER_BASE}${encodeURIComponent(did)}`;

  const response = await fetch(url, {
    headers: {
      Accept: 'application/did+ld+json',
    },
  });

  if (!response.ok) {
    throw new Error(`cheqd resolver returned ${response.status}: ${await response.text()}`);
  }

  const result = (await response.json()) as unknown;
  if (!result || typeof result !== 'object') {
    throw new Error('cheqd resolver returned invalid JSON');
  }

  const rec = result as Record<string, unknown>;
  // Universal-resolver shape
  if (rec.didDocument && typeof rec.didDocument === 'object') {
    return rec.didDocument as DIDDocument;
  }
  // cheqd driver returns the DID document as the root JSON-LD object
  if (
    typeof rec.id === 'string' &&
    rec.id.startsWith('did:') &&
    Array.isArray(rec.verificationMethod)
  ) {
    return result as DIDDocument;
  }

  throw new Error('cheqd resolver returned no usable DID document');
}

/**
 * Method-specific resolvers delegate to the HTTP universal resolver (did:web only).
 */
function createUniversalDidResolver(): DIDResolver {
  return async (
    did: string,
    parsed: ParsedDID,
    resolver: Resolvable,
    options: DIDResolutionOptions
  ): Promise<DIDResolutionResult> => {
    void parsed;
    void resolver;
    void options;
    const didDocument = await resolveViaUniversalBinding(did);
    return {
      didDocument,
      didDocumentMetadata: {},
      didResolutionMetadata: { contentType: 'application/did+json' },
    };
  };
}

const resolver = new Resolver({
  web: createUniversalDidResolver(),
});

/**
 * Resolve a DID to its DID document (verification methods, etc.).
 * did:key is resolved locally; did:cheqd uses resolver.cheqd.net; did:web uses the universal resolver.
 */
export async function resolveDidDocument(did: string): Promise<DIDDocument> {
  if (!did || typeof did !== 'string' || !did.startsWith('did:')) {
    throw new Error(`Invalid DID: ${did}`);
  }

  const fragmentIndex = did.indexOf('#');
  const didWithoutFragment = fragmentIndex >= 0 ? did.slice(0, fragmentIndex) : did;

  if (didWithoutFragment.startsWith('did:key:')) {
    return resolveDidKeyLocally(didWithoutFragment);
  }

  if (didWithoutFragment.startsWith('did:cheqd:')) {
    return resolveCheqdDidDirectly(didWithoutFragment);
  }

  const method = didWithoutFragment.split(':')[1];

  if (!method) {
    throw new Error(`Invalid DID (no method): ${did}`);
  }

  const supported = new Set(['web']);
  if (!supported.has(method)) {
    throw new Error(`Unsupported DID method for resolver: ${method}`);
  }

  const result = await resolver.resolve(didWithoutFragment);
  const doc = result.didDocument;

  if (!doc) {
    throw new Error(`DID could not be resolved: ${didWithoutFragment}`);
  }

  return doc as DIDDocument;
}
