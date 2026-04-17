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
 * P-256: multicodec prefix 0xed 0x01 + 32-byte public key.
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
    throw new Error('Only P-256 did:key is supported (multicodec 0xed01)');
  }

  const publicKeyBytes = multicodecBytes.subarray(2);
  if (publicKeyBytes.length !== 32) {
    throw new Error(`Invalid P-256 public key length: ${publicKeyBytes.length}`);
  }

  const verificationMethodId = `${did}#${keyPart}`;

  return {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: did,
    verificationMethod: [
      {
        id: verificationMethodId,
        type: 'JsonWebKey2020',
        controller: did,
        publicKeyJwk: {
          kty: 'EC',
          crv: 'P-256',
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
const FALLBACK_UNIVERSAL_RESOLVER_URL = 'https://dev.uniresolver.io/1.0/identifiers/';

export interface UniversalResolverResponse {
  didDocument?: DidResolverDocument;
  didResolutionMetadata?: Record<string, unknown>;
  didDocumentMetadata?: Record<string, unknown>;
}

async function resolveViaUniversalBinding(
  did: string,
  resolverUrl?: string
): Promise<DidResolverDocument> {
  const url = `${resolverUrl ?? FALLBACK_UNIVERSAL_RESOLVER_URL}${encodeURIComponent(did)}`;
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
 * Method-specific resolvers delegate to the HTTP universal resolver (did:web and did:cheqd).
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
    const didDocument = await resolveViaUniversalBinding(
      did,
      (options as DIDResolutionOptions & { resolverUrl?: string }).resolverUrl
    );
    return {
      didDocument,
      didDocumentMetadata: {},
      didResolutionMetadata: { contentType: 'application/did+json' },
    };
  };
}

const resolver = new Resolver({
  web: createUniversalDidResolver(),
  cheqd: createUniversalDidResolver(),
});

/**
 * Resolve a DID to its DID document (verification methods, etc.).
 * did:key is resolved locally; did:cheqd uses resolver.cheqd.net; did:web uses the universal resolver.
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

  const supported = new Set(['web', 'cheqd']);
  if (!supported.has(method)) {
    throw new Error(`Unsupported DID method for resolver: ${method}`);
  }

  const result = await resolver.resolve(didWithoutFragment, {
    resolverUrl,
  } as DIDResolutionOptions & { resolverUrl?: string });
  const doc = result.didDocument;

  if (!doc) {
    throw new Error(`DID could not be resolved: ${didWithoutFragment}`);
  }

  return doc as DIDDocument;
}
