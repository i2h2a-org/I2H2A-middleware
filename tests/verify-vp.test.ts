import * as crypto from 'crypto';
import { checkCredentialStatus } from '../src/check-status';
import { resolveDidDocument } from '../src/resolve-did';
import type { CredentialStatusEntry, DIDDocument, P256Jwk } from '../src/types';
import { verifyI2H2APresentation } from '../src/verify-vp';

jest.mock('../src/resolve-did');
jest.mock('../src/check-status');

const mockedResolve = resolveDidDocument as jest.MockedFunction<typeof resolveDidDocument>;
const mockedStatus = checkCredentialStatus as jest.MockedFunction<typeof checkCredentialStatus>;

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

describe('verifyI2H2APresentation', () => {
  const issuerDid = 'did:key:test-issuer';
  const mcpServerId = 'test-server';
  const nonce = 'test-nonce';

  let issuerKeys: crypto.KeyPairKeyObjectResult;
  let holderKeys: crypto.KeyPairKeyObjectResult;
  let holderJwk: P256Jwk;
  let issuerJwk: P256Jwk;

  beforeEach(() => {
    issuerKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    holderKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    holderJwk = holderKeys.publicKey.export({ format: 'jwk' }) as P256Jwk;
    issuerJwk = issuerKeys.publicKey.export({ format: 'jwk' }) as P256Jwk;

    mockedResolve.mockImplementation(async () => makeDidDoc(issuerDid, issuerJwk));
    mockedStatus.mockResolvedValue(true);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  function buildToken(opts?: {
    delegatedBy?: string;
    mcpServers?: string[];
    delegationDepth?: number;
    parentCredential?: string | null;
    status?: CredentialStatusEntry;
  }): string {
    const now = Math.floor(Date.now() / 1000);
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
        Buffer.from(JSON.stringify(['s4', 'scope.mcpServers', opts?.mcpServers ?? [mcpServerId]]))
      ),
      b64urlEncode(Buffer.from(JSON.stringify(['s5', 'scope.taskType', 'read-only']))),
      b64urlEncode(Buffer.from(JSON.stringify(['s6', 'authorization', { role: 'read' }]))),
    ];

    const issuerPayload = {
      iss: issuerDid,
      sub: 'did:key:test-agent',
      iat: now,
      nbf: now,
      exp: now + 3600,
      vct: 'I2H2A' as const,
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
    const kbPayload = {
      iat: now,
      aud: mcpServerId,
      nonce,
      sd_hash: crypto.createHash('sha256').update(sdInput, 'utf8').digest('base64url'),
    };
    const kbJwt = signEs256Jwt({ alg: 'ES256', typ: 'JWT' }, kbPayload, holderKeys.privateKey);
    return `${sdInput}${kbJwt}`;
  }

  it('accepts a valid SD-JWT+KB presentation', async () => {
    const token = buildToken();
    const res = await verifyI2H2APresentation(token, {
      mcpServerId,
      nonce,
      skipStatusCheck: true,
    });
    expect(res.valid).toBe(true);
    expect(res.claims?.agentDid).toBe('did:key:test-agent');
  });

  it('rejects when MCP server is not permitted', async () => {
    const token = buildToken({ mcpServers: ['other-server'] });
    const res = await verifyI2H2APresentation(token, {
      mcpServerId,
      nonce,
      skipStatusCheck: true,
    });
    expect(res.valid).toBe(false);
    expect(res.error).toBe('Delegation scope does not permit this MCP server');
  });

  it('rejects revoked credential from status check', async () => {
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

  it('rejects invalid delegatedBy value', async () => {
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
