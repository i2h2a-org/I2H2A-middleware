/**
 * End-to-end integration: issue I2H2A VC via cheqd Studio API, wrap in agent-signed VP JWT, verify with middleware.
 *
 * Requires: .env with CHEQD_API_KEY, HUMAN_DID (did:cheqd). Optional: CHEQD_NETWORK (default testnet).
 * Optional: SKIP_STATUS_CHECK=true if status list cannot be fetched.
 *
 * Run: npm run test:real
 */

import 'dotenv/config';
import * as crypto from 'crypto';
import * as ed from '@noble/ed25519';
import jwt, { type JwtHeader, type JwtPayload } from 'jsonwebtoken';
import { verifyI2H2APresentation } from '../src/index';
import { resolveDidDocument } from '../src/resolve-did';
import {
  extractVpPayloadFromJwt,
  parseDidAndFragment,
  pickSigningJwk,
  publicKeyFromJwk,
  verifyJwtWithKey,
} from '../src/verify-helpers';

const CHEQD_ISSUE_URL = 'https://studio-api.cheqd.net/credential/issue';

const MULTICODEC_ED25519_PUB = new Uint8Array([0xed, 0x01]);

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58BtcEncode(bytes: Uint8Array): string {
  let zeros = 0;
  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) {
    zeros++;
  }

  let n = 0n;
  for (const b of bytes) {
    n = (n << 8n) + BigInt(b);
  }

  let output = '';
  while (n > 0n) {
    const rem = Number(n % 58n);
    n = n / 58n;
    output = BASE58_ALPHABET[rem] + output;
  }

  return '1'.repeat(zeros) + (output || '');
}

function base64UrlEncode(data: Buffer | Uint8Array): string {
  return Buffer.from(data)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function buildDidKeyFromP256PublicKey(publicKey: Uint8Array): string {
  const prefixed = new Uint8Array(MULTICODEC_ED25519_PUB.length + publicKey.length);
  prefixed.set(MULTICODEC_ED25519_PUB, 0);
  prefixed.set(publicKey, MULTICODEC_ED25519_PUB.length);
  return `did:key:z${base58BtcEncode(prefixed)}`;
}

/**
 * Build a compact JWS (ES256 / P-256). `jsonwebtoken.sign` signs ES256 directly,
 * so we sign the signing input with @noble/ed25519 and still use `jsonwebtoken` only to sanity-check parsing.
 */
async function signVpJwtEs256(
  header: Record<string, string>,
  payload: Record<string, unknown>,
  secretKey: Uint8Array
): Promise<string> {
  const headerB64 = base64UrlEncode(Buffer.from(JSON.stringify(header)));
  const payloadB64 = base64UrlEncode(Buffer.from(JSON.stringify(payload)));
  const msg = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const sig = await ed.signAsync(msg, secretKey);
  const sigB64 = base64UrlEncode(Buffer.from(sig));
  const token = `${headerB64}.${payloadB64}.${sigB64}`;
  if (jwt.decode(token, { complete: true }) == null) {
    throw new Error('Signed VP JWT failed jsonwebtoken decode sanity check');
  }
  return token;
}

function findJwtStringDeep(value: unknown, maxDepth = 14): string | undefined {
  if (maxDepth < 0) {
    return undefined;
  }
  if (typeof value === 'string' && value.startsWith('eyJ')) {
    return value;
  }
  if (!value || typeof value !== 'object') {
    return undefined;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      const found = findJwtStringDeep(item, maxDepth - 1);
      if (found) {
        return found;
      }
    }
    return undefined;
  }
  const o = value as Record<string, unknown>;
  for (const k of Object.keys(o)) {
    const found = findJwtStringDeep(o[k], maxDepth - 1);
    if (found) {
      return found;
    }
  }
  return undefined;
}

/** Pull VC-JWT from typical cheqd Studio shapes (top-level, nested, or `proof.jws`). */
function extractJwtFromIssueResponse(data: unknown): string {
  if (typeof data === 'string' && data.startsWith('eyJ')) {
    return data;
  }
  if (!data || typeof data !== 'object') {
    throw new Error(`Unexpected issue response type: ${typeof data}`);
  }
  const o = data as Record<string, unknown>;
  const shallow = [
    o.credential,
    o.jwt,
    o.vcJwt,
    o.vc_jwt,
    o.compactJwt,
    o.compact_jwt,
    o.verifiableCredential,
    (o.data as Record<string, unknown> | undefined)?.credential,
    (o.data as Record<string, unknown> | undefined)?.jwt,
    (o.result as Record<string, unknown> | undefined)?.jwt,
  ];
  for (const v of shallow) {
    if (typeof v === 'string' && v.startsWith('eyJ')) {
      return v;
    }
  }

  const deep = findJwtStringDeep(data);
  if (deep) {
    return deep;
  }

  throw new Error(`No JWT credential in API response: ${JSON.stringify(data).slice(0, 1200)}`);
}

interface RunSummary {
  humanDid: string;
  agentDid: string;
  credentialIssued: boolean;
  vpVerified: boolean;
  error?: string;
}

/**
 * When middleware reports credential signature failure, re-run resolution + verify with full logs.
 */
async function debugCredentialJwtVerification(vpJwt: string): Promise<void> {
  console.log('\n--- Debug: manual I2H2A credential JWT verification ---');
  try {
    const vpComplete = jwt.decode(vpJwt, { complete: true });
    if (!vpComplete || typeof vpComplete !== 'object' || !('payload' in vpComplete)) {
      console.error('Could not decode VP JWT (complete)');
      return;
    }

    const vpRecord = extractVpPayloadFromJwt(vpComplete.payload as JwtPayload);
    const vcArr = vpRecord.verifiableCredential;
    if (!Array.isArray(vcArr) || vcArr.length === 0) {
      console.error('VP has no verifiableCredential[] or it is empty');
      return;
    }

    const cred0 = vcArr[0];
    console.log('verifiableCredential[0] typeof:', typeof cred0);

    if (typeof cred0 !== 'string' || !cred0.startsWith('eyJ')) {
      console.log(
        'verifiableCredential[0] is not a compact JWT string; preview:',
        JSON.stringify(cred0).slice(0, 500)
      );
      return;
    }

    const credJwt = cred0;
    const credComplete = jwt.decode(credJwt, { complete: true });
    if (!credComplete || typeof credComplete !== 'object') {
      console.error('Could not decode credential JWT (complete)');
      return;
    }

    console.log('Credential JWT header:', JSON.stringify(credComplete.header, null, 2));
    console.log('Credential JWT payload:', JSON.stringify(credComplete.payload, null, 2));

    const credHdr = credComplete.header as JwtHeader;
    const credPl = credComplete.payload as JwtPayload & Record<string, unknown>;
    const iss = typeof credPl.iss === 'string' ? credPl.iss : undefined;
    if (!iss) {
      console.error('Credential JWT has no string iss; cannot resolve issuer DID');
      return;
    }
    console.log('Issuer DID (from credential JWT iss):', iss);

    const { did: issuerBase } = parseDidAndFragment(iss);
    let holderDoc;
    try {
      holderDoc = await resolveDidDocument(issuerBase);
    } catch (resolveErr: unknown) {
      console.error('resolveDidDocument(issuer) failed:');
      if (resolveErr instanceof Error) {
        console.error(resolveErr.message);
        console.error(resolveErr.stack ?? '');
      }
      console.error(JSON.stringify(resolveErr, Object.getOwnPropertyNames(resolveErr as object), 2));
      return;
    }

    console.log('Resolved issuer DID document:', JSON.stringify(holderDoc, null, 2));
    console.log(
      'Issuer verificationMethod[]:',
      JSON.stringify(holderDoc.verificationMethod ?? [], null, 2)
    );

    const kid = typeof credHdr.kid === 'string' ? credHdr.kid : undefined;
    let jwk: crypto.JsonWebKey;
    try {
      jwk = pickSigningJwk(holderDoc, iss, kid);
    } catch (pickErr: unknown) {
      console.error('pickSigningJwk failed:');
      if (pickErr instanceof Error) {
        console.error(pickErr.message);
      }
      console.error(JSON.stringify(pickErr, Object.getOwnPropertyNames(pickErr as object), 2));
      return;
    }

    console.log('JWK selected for credential verification (iss + kid, same as middleware):');
    console.log(JSON.stringify(jwk, null, 2));

    try {
      verifyJwtWithKey(credJwt, publicKeyFromJwk(jwk));
      console.log('Manual credential JWT verification: SUCCESS (verifyJwtWithKey)');
    } catch (err: unknown) {
      console.error('Manual credential JWT verification: FAILED');
      if (err instanceof Error) {
        console.error('name:', err.name);
        console.error('message:', err.message);
        if (err.stack) {
          console.error('stack:', err.stack);
        }
      }
      try {
        console.error(
          'serialized:',
          JSON.stringify(err, Object.getOwnPropertyNames(err as object), 2)
        );
      } catch {
        console.error('raw error:', err);
      }
    }
  } catch (e) {
    console.error('debugCredentialJwtVerification threw:', e);
  }
}

async function main(): Promise<void> {
  const summary: RunSummary = {
    humanDid: '',
    agentDid: '',
    credentialIssued: false,
    vpVerified: false,
  };

  let agentSecretKey: Uint8Array | undefined;
  let i2h2aCredentialJwt: string | undefined;

  try {
    // --- 1. Environment ---
    try {
      const apiKey = process.env.CHEQD_API_KEY?.trim();
      const humanDid = process.env.HUMAN_DID?.trim();
      const network = (process.env.CHEQD_NETWORK ?? 'testnet').trim();

      if (!apiKey) {
        throw new Error('CHEQD_API_KEY is required in .env');
      }
      if (!humanDid) {
        throw new Error('HUMAN_DID is required in .env (issuer did:cheqd)');
      }
      if (!humanDid.startsWith('did:cheqd:')) {
        throw new Error('HUMAN_DID must be a did:cheqd identifier');
      }

      summary.humanDid = humanDid;
      console.log(`Using cheqd network (informational): ${network}`);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      console.error(`Environment error: ${msg}`);
      summary.error = msg;
      printSummary(summary);
      process.exitCode = 1;
      return;
    }

    // --- 2. Ephemeral agent did:key ---
    try {
      agentSecretKey = ed.utils.randomPrivateKey();
      const publicKey = await ed.getPublicKeyAsync(agentSecretKey);
      summary.agentDid = buildDidKeyFromP256PublicKey(publicKey);
      console.log(`✓ Agent did:key generated: ${summary.agentDid}`);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      console.error(`Agent DID generation failed: ${msg}`);
      summary.error = msg;
      printSummary(summary);
      process.exitCode = 1;
      return;
    }

    const humanDid = summary.humanDid;
    const agentDid = summary.agentDid;
    const apiKey = process.env.CHEQD_API_KEY!.trim();

    // --- 3. Issue credential via cheqd Studio ---
    try {
      const validFrom = new Date().toISOString();
      const validUntil = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

      const body = {
        issuerDid: humanDid,
        subjectDid: agentDid,
        attributes: {
          '@context': ['https://www.w3.org/2018/credentials/v1'],
          type: ['VerifiableCredential', 'I2H2A'],
          credentialSubject: {
            id: agentDid,
            scope: {
              mcpServers: ['amazon-mcp'],
              taskType: 'product_search',
              constraints: { maxPrice: 500 },
            },
            authorization: {
              platform: 'test',
              sessionId: 'integration-test-session',
            },
            delegatedBy: humanDid,
            parentCredential: null,
            delegationDepth: 0,
          },
          validFrom,
          validUntil,
          credentialStatus: {
            type: 'BitstringStatusListEntry',
            statusPurpose: 'revocation',
            ...(process.env.CHEQD_STATUS_LIST_NAME
              ? { statusListName: process.env.CHEQD_STATUS_LIST_NAME.trim() }
              : {}),
          },
        },
        format: 'jwt',
        credentialSchema: 'https://schema.org/I2H2A',
      };

      const res = await fetch(CHEQD_ISSUE_URL, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
          'x-api-key': apiKey,
        },
        body: JSON.stringify(body),
      });

      const text = await res.text();
      let json: unknown;
      try {
        json = JSON.parse(text) as unknown;
      } catch {
        json = { raw: text };
      }

      if (!res.ok) {
        throw new Error(`cheqd issue failed HTTP ${res.status}: ${text.slice(0, 600)}`);
      }

      i2h2aCredentialJwt = extractJwtFromIssueResponse(json);
      summary.credentialIssued = true;
      const preview = `${i2h2aCredentialJwt.slice(0, 48)}…${i2h2aCredentialJwt.slice(-24)}`;
      console.log(`✓ I2H2A credential issued: ${preview}`);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      console.error(`Credential issuance failed: ${msg}`);
      summary.error = msg;
      printSummary(summary);
      process.exitCode = 1;
      return;
    }

    // --- 4. Presentation JWT signed by agent (P-256 / ES256) ---
    let vpJwt: string;
    try {
      const nowSec = Math.floor(Date.now() / 1000);
      const vpBody = {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['string'],
        holder: agentDid,
        verifiableCredential: [i2h2aCredentialJwt],
      };

      const vpPayload: Record<string, unknown> = {
        iss: agentDid,
        aud: 'amazon-mcp',
        vp: vpBody,
        iat: nowSec,
        exp: nowSec + 3600,
      };

      const header = {
        alg: 'ES256',
        typ: 'JWT',
        kid: `${agentDid}#key-1`,
      };

      vpJwt = await signVpJwtEs256(header, vpPayload, agentSecretKey!);
      console.log('✓ VP constructed and signed by agent');
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      console.error(`VP signing failed: ${msg}`);
      summary.error = msg;
      printSummary(summary);
      process.exitCode = 1;
      return;
    }

    // --- 5. Verify with middleware ---
    try {
      const skipStatus =
        process.env.SKIP_STATUS_CHECK === '1' ||
        process.env.SKIP_STATUS_CHECK === 'true';

      console.log('\n--- Step 5 debug: VP JWT structure ---');
      const vpDecoded = jwt.decode(vpJwt, { complete: true });
      if (!vpDecoded || typeof vpDecoded !== 'object') {
        console.error('jwt.decode(complete) returned null or invalid');
      } else {
        console.log('VP JWT header:', JSON.stringify(vpDecoded.header, null, 2));
        console.log('VP JWT payload:', JSON.stringify(vpDecoded.payload, null, 2));
        const vpParts = vpJwt.split('.');
        const sigPart = vpParts.length >= 3 ? vpParts[2] : '';
        console.log('VP JWT signature (3rd segment, base64url):', sigPart || '(missing)');
      }

      console.log('\n--- Step 5 debug: agent DID resolution ---');
      try {
        const { did: agentDidBase } = parseDidAndFragment(agentDid);
        const agentDoc = await resolveDidDocument(agentDidBase);
        console.log('Agent DID (full):', agentDid);
        console.log('Resolved DID document:', JSON.stringify(agentDoc, null, 2));
        console.log(
          'verificationMethod[]:',
          JSON.stringify(agentDoc.verificationMethod ?? [], null, 2)
        );

        const hdr =
          vpDecoded && typeof vpDecoded === 'object' && 'header' in vpDecoded
            ? (vpDecoded.header as JwtHeader)
            : ({} as JwtHeader);
        const pl =
          vpDecoded && typeof vpDecoded === 'object' && 'payload' in vpDecoded
            ? (vpDecoded.payload as JwtPayload)
            : ({} as JwtPayload);
        const iss = typeof pl.iss === 'string' ? pl.iss : agentDid;
        const kid = typeof hdr.kid === 'string' ? hdr.kid : undefined;
        const verificationJwk = pickSigningJwk(agentDoc, iss, kid);
        console.log(
          'Public key JWK selected for VP verification (iss + kid, same as middleware):',
          JSON.stringify(verificationJwk, null, 2)
        );
      } catch (resolveErr: unknown) {
        console.error('Agent DID resolution / key selection (debug) failed:');
        if (resolveErr instanceof Error) {
          console.error(resolveErr.message);
        }
        console.error(JSON.stringify(resolveErr, Object.getOwnPropertyNames(resolveErr as object), 2));
      }

      console.log('\n--- Step 5: verifyI2H2APresentation ---');
      let result: Awaited<ReturnType<typeof verifyI2H2APresentation>>;
      try {
        result = await verifyI2H2APresentation(vpJwt, {
          mcpServerId: 'amazon-mcp',
          taskType: 'product_search',
          ...(skipStatus ? { skipStatusCheck: true } : {}),
        });
      } catch (verifyErr: unknown) {
        console.error('verifyI2H2APresentation threw an exception:');
        if (verifyErr instanceof Error && verifyErr.message) {
          console.error('message:', verifyErr.message);
        }
        if (verifyErr !== null && typeof verifyErr === 'object') {
          try {
            console.error('error object:', JSON.stringify(verifyErr, null, 2));
          } catch {
            console.error('error (could not stringify):', verifyErr);
          }
        } else {
          console.error('error:', String(verifyErr));
        }
        throw verifyErr;
      }

      if (result.valid) {
        summary.vpVerified = true;
        console.log('✓ VP verification PASSED');
        console.log('Claims:', JSON.stringify(result.claims, null, 2));
      } else {
        console.error(`✗ VP verification FAILED: ${result.error ?? 'unknown error'}`);
        summary.error = result.error;
        if (result.error === 'I2H2A credential signature verification failed') {
          await debugCredentialJwtVerification(vpJwt);
        }
      }
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      console.error(`✗ VP verification step FAILED: ${msg}`);
      if (e instanceof Error && e.message) {
        console.error('message:', e.message);
      }
      if (e !== null && typeof e === 'object') {
        try {
          console.error(JSON.stringify(e, null, 2));
        } catch {
          console.error(e);
        }
      }
      summary.error = msg;
    }

    printSummary(summary);
    process.exitCode = summary.vpVerified && !summary.error ? 0 : 1;
  } finally {
    if (agentSecretKey) {
      crypto.randomFillSync(agentSecretKey);
    }
  }
}

function printSummary(s: RunSummary): void {
  console.log('\n--- Summary ---');
  console.log(`Human DID: ${s.humanDid || '(not set)'}`);
  console.log(`Agent DID: ${s.agentDid || '(not generated)'}`);
  console.log(`Credential issued: ${s.credentialIssued ? 'YES' : 'NO'}`);
  console.log(`VP verified: ${s.vpVerified ? 'YES' : 'NO'}`);
  const pass = s.credentialIssued && s.vpVerified && !s.error;
  console.log(`Test result: ${pass ? 'PASS' : 'FAIL'}`);
  if (s.error) {
    console.log(`Last error: ${s.error}`);
  }
}

main()
  .then(() => {
    process.exit(process.exitCode ?? 0);
  })
  .catch((e) => {
    console.error(e);
    process.exit(1);
  });
