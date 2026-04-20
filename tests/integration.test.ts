import * as crypto from 'crypto';
import { checkCredentialStatus } from '../src/check-status';
import { resolveDidDocument } from '../src/resolve-did';
import type { CredentialStatusEntry, DIDDocument, P256Jwk } from '../src/types';
import { verifyI2H2APresentation } from '../src/verify-vp';

jest.mock('../src/resolve-did');
jest.mock('../src/check-status');

const mockedResolve = resolveDidDocument as jest.MockedFunction<typeof resolveDidDocument>;
const mockedStatus = checkCredentialStatus as jest.MockedFunction<typeof checkCredentialStatus>;

function makeDidDoc(did: string, publicJwk: P256Jwk): DIDDocument {
  return {
    id: did,
    verificationMethod: [
      {
        id: `${did}#key-1`,
        type: 'JsonWebKey2020',
        controller: did,
        publicKeyJwk: publicJwk,
      },
    ],
  };
}

function b64urlEncode(input: Buffer | string): string {
  return Buffer.from(input).toString('base64url');
}

function signEs256Jwt(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  privateKey: crypto.KeyObject
): string {
  const headerB64 = b64urlEncode(Buffer.from(JSON.stringify(header), 'utf8'));
  const payloadB64 = b64urlEncode(Buffer.from(JSON.stringify(payload), 'utf8'));
  const signingInput = `${headerB64}.${payloadB64}`;
  const signature = crypto.sign('SHA256', Buffer.from(signingInput, 'utf8'), {
    key: privateKey,
    dsaEncoding: 'ieee-p1363',
  });
  return `${signingInput}.${b64urlEncode(signature)}`;
}

function disclosureHash(disclosureB64: string): string {
  return crypto.createHash('sha256').update(disclosureB64, 'utf8').digest('base64url');
}

describe('integration (mocked resolver and status)', () => {
  const issuerDid = 'did:key:test-issuer';
  const agentDid = 'did:key:test-agent';
  const mcpServerId = 'test-server';
  const nonce = 'test-nonce';

  let issuerKeys: crypto.KeyPairKeyObjectResult;
  let holderKeys: crypto.KeyPairKeyObjectResult;
  let holderJwk: P256Jwk;
  let issuerJwk: P256Jwk;

  beforeEach(() => {
    const ecOpts = { namedCurve: 'P-256' as const };
    issuerKeys = crypto.generateKeyPairSync('ec', ecOpts);
    holderKeys = crypto.generateKeyPairSync('ec', ecOpts);
    holderJwk = holderKeys.publicKey.export({ format: 'jwk' }) as P256Jwk;
    issuerJwk = issuerKeys.publicKey.export({ format: 'jwk' }) as P256Jwk;

    mockedResolve.mockImplementation(async (did: string) => {
      if (did === issuerDid) return makeDidDoc(issuerDid, issuerJwk);
      throw new Error(`unexpected DID: ${did}`);
    });

    mockedStatus.mockResolvedValue(true);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  function buildToken(opts?: {
    exp?: number;
    delegationDepth?: number;
    parentCredential?: string | null;
    scopeServer?: string[];
    authorization?: unknown;
    delegatedBy?: string;
    status?: CredentialStatusEntry;
    kbNonce?: string;
    kbAud?: string;
    signKbWithWrongKey?: boolean;
    badSdHash?: boolean;
  }): string {
    const nowSec = Math.floor(Date.now() / 1000);
    const hasAuthorizationOverride =
      opts != null && Object.prototype.hasOwnProperty.call(opts, 'authorization');
    const disclosures = [
      b64urlEncode(
        Buffer.from(JSON.stringify(['s1', 'delegatedBy', opts?.delegatedBy ?? 'did:example:holder']))
      ),
      b64urlEncode(
        Buffer.from(JSON.stringify(['s2', 'delegationDepth', opts?.delegationDepth ?? 0]))
      ),
      b64urlEncode(
        Buffer.from(JSON.stringify(['s3', 'parentCredential', opts?.parentCredential ?? null]))
      ),
      b64urlEncode(
        Buffer.from(JSON.stringify(['s4', 'scope.mcpServers', opts?.scopeServer ?? [mcpServerId]]))
      ),
      b64urlEncode(Buffer.from(JSON.stringify(['s5', 'scope.taskType', 'read-only']))),
      b64urlEncode(
        Buffer.from(
          JSON.stringify([
            's6',
            'authorization',
            hasAuthorizationOverride ? opts?.authorization : { delegationDepth: 0, parentCredential: null },
          ])
        )
      ),
    ];

    const issuerPayload = {
      iss: issuerDid,
      sub: agentDid,
      iat: nowSec,
      nbf: nowSec,
      exp: opts?.exp ?? nowSec + 3600,
      vct: 'https://rotavera.io/credentials/I2H2A' as const,
      cnf: { jwk: holderJwk },
      credentialStatus:
        opts?.status ??
        ({
          id: 'https://example.org/status/1#0',
          type: 'BitstringStatusListEntry' as const,
          statusListIndex: 0,
          statusListCredential: 'https://example.org/status/1',
        } satisfies CredentialStatusEntry),
      _sd_alg: 'sha-256' as const,
      _sd: disclosures.map(disclosureHash),
    };

    const issuerJwt = signEs256Jwt({ alg: 'ES256', typ: 'JWT' }, issuerPayload, issuerKeys.privateKey);
    const sdInput = `${issuerJwt}~${disclosures.join('~')}~`;
    const sdHash = opts?.badSdHash
      ? 'bad-hash'
      : crypto.createHash('sha256').update(sdInput, 'utf8').digest('base64url');
    const kbPayload = {
      iat: nowSec,
      aud: opts?.kbAud ?? mcpServerId,
      nonce: opts?.kbNonce ?? nonce,
      sd_hash: sdHash,
    };
    const kbSigner = opts?.signKbWithWrongKey
      ? crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey
      : holderKeys.privateKey;
    const kbJwt = signEs256Jwt({ alg: 'ES256', typ: 'JWT' }, kbPayload, kbSigner);
    return `${sdInput}${kbJwt}`;
  }

  it('valid token with matching mcpServerId returns valid=true with correct claims', async () => {
    const token = buildToken();
    const res = await verifyI2H2APresentation(token, {
      mcpServerId,
      nonce,
      skipStatusCheck: true,
    });

    expect(res.valid).toBe(true);
    expect(res.claims).toMatchObject({
      agentDid,
      delegatedBy: 'did:example:holder',
      scope: { mcpServers: [mcpServerId], taskType: 'read-only' },
      authorization: { delegationDepth: 0, parentCredential: null },
    });
  });

  it('token with mismatched mcpServerId returns valid=false', async () => {
    const token = buildToken({ kbAud: 'different-server' });
    const res = await verifyI2H2APresentation(token, {
      mcpServerId: 'different-server',
      nonce,
      skipStatusCheck: true,
    });

    expect(res.valid).toBe(false);
    expect(res.error).toBe('Delegation scope does not permit this MCP server');
  });

  it('token with mismatched nonce returns valid=false', async () => {
    const token = buildToken({ kbNonce: 'other-nonce' });
    const res = await verifyI2H2APresentation(token, {
      mcpServerId,
      nonce,
      skipStatusCheck: true,
    });

    expect(res.valid).toBe(false);
    expect(res.error).toBe('KB-JWT nonce mismatch');
  });

  it('token with revoked credential returns valid=false', async () => {
    mockedStatus.mockResolvedValueOnce(false);
    const token = buildToken();
    const res = await verifyI2H2APresentation(token, {
      mcpServerId,
      nonce,
      skipStatusCheck: false,
    });

    expect(res.valid).toBe(false);
    expect(res.error).toBe('Credential revoked');
  });

  it('token with expired credential returns valid=false', async () => {
    const nowSec = Math.floor(Date.now() / 1000);
    const token = buildToken({ exp: nowSec - 60 });
    const res = await verifyI2H2APresentation(token, {
      mcpServerId,
      nonce,
      skipStatusCheck: true,
    });

    expect(res.valid).toBe(false);
    expect(res.error).toBe('Issuer JWT expired');
  });

  it('token with invalid kb signature returns valid=false', async () => {
    const token = buildToken({ signKbWithWrongKey: true });
    const res = await verifyI2H2APresentation(token, {
      mcpServerId,
      nonce,
      skipStatusCheck: true,
    });

    expect(res.valid).toBe(false);
    expect(res.error).toBe('KB-JWT signature invalid');
  });

  it('token with bad sd_hash returns valid=false', async () => {
    const token = buildToken({ badSdHash: true });
    const res = await verifyI2H2APresentation(token, {
      mcpServerId,
      nonce,
      skipStatusCheck: true,
    });

    expect(res.valid).toBe(false);
    expect(res.error).toBe('KB-JWT sd_hash mismatch');
  });

  it('token with delegationDepth != 0 returns valid=false', async () => {
    const token = buildToken({ delegationDepth: 1 });
    const res = await verifyI2H2APresentation(token, {
      mcpServerId,
      nonce,
      skipStatusCheck: true,
    });

    expect(res.valid).toBe(false);
    expect(res.error).toBe('Invalid delegation depth (must be 0 for V1)');
  });

  it('token with parentCredential != null returns valid=false', async () => {
    const token = buildToken({ parentCredential: 'urn:vc:parent:1' });
    const res = await verifyI2H2APresentation(token, {
      mcpServerId,
      nonce,
      skipStatusCheck: true,
    });

    expect(res.valid).toBe(false);
    expect(res.error).toBe('Parent credential must be null for H2A (V1)');
  });

  it('token allows missing authorization and returns null authorization', async () => {
    const token = buildToken({ authorization: undefined });
    const res = await verifyI2H2APresentation(token, {
      mcpServerId,
      nonce,
      skipStatusCheck: true,
    });

    expect(res.valid).toBe(true);
    expect(res.claims?.authorization).toBeNull();
  });

  it('token returns error when delegatedBy is absent', async () => {
    const token = buildToken({ delegatedBy: '' });
    const res = await verifyI2H2APresentation(token, {
      mcpServerId,
      nonce,
      skipStatusCheck: true,
    });

    expect(res.valid).toBe(false);
    expect(res.error).toBe('delegatedBy is required');
  });
});
