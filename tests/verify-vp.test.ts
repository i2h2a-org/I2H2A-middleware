import * as crypto from 'crypto';
import jwt, { type SignOptions } from 'jsonwebtoken';
import { checkCredentialStatus } from '../src/check-status';
import { resolveDidDocument } from '../src/resolve-did';
import { verifyI2H2AVP } from '../src/verify-vp';

jest.mock('../src/resolve-did');
jest.mock('../src/check-status');

const mockedResolve = resolveDidDocument as jest.MockedFunction<typeof resolveDidDocument>;
const mockedStatus = checkCredentialStatus as jest.MockedFunction<typeof checkCredentialStatus>;

function makeDidDoc(did: string, publicJwk: crypto.JsonWebKey) {
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

describe('verifyI2H2AVP', () => {
  const holderDid = 'did:key:test-holder';
  const agentDid = 'did:key:test-agent';

  let holderKeys: crypto.KeyPairKeyObjectResult;
  let agentKeys: crypto.KeyPairKeyObjectResult;

  beforeEach(() => {
    const ecOpts = { namedCurve: 'P-256' as const };
    holderKeys = crypto.generateKeyPairSync('ec', ecOpts);
    agentKeys = crypto.generateKeyPairSync('ec', ecOpts);

    mockedResolve.mockImplementation(async (did: string) => {
      const holderPub = holderKeys.publicKey.export({ format: 'jwk' }) as crypto.JsonWebKey;
      const agentPub = agentKeys.publicKey.export({ format: 'jwk' }) as crypto.JsonWebKey;
      if (did === holderDid) {
        return makeDidDoc(holderDid, holderPub);
      }
      if (did === agentDid) {
        return makeDidDoc(agentDid, agentPub);
      }
      throw new Error(`unexpected DID: ${did}`);
    });

    mockedStatus.mockResolvedValue(true);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  function buildVcJwt(opts?: { exp?: number; authorization?: unknown; delegatedBy?: string }) {
    const nowSec = Math.floor(Date.now() / 1000);
    const hasAuthorizationOverride =
      opts != null && Object.prototype.hasOwnProperty.call(opts, 'authorization');
    const vcBody = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential', 'I2H2A'],
      issuer: holderDid,
      credentialSubject: {
        id: agentDid,
        scope: { mcpServers: ['allowed-server'], taskType: 'read' },
        authorization: hasAuthorizationOverride
          ? opts?.authorization
          : { delegationDepth: 0, parentCredential: null },
        delegatedBy: opts?.delegatedBy ?? holderDid,
        delegationDepth: 0,
        parentCredential: null,
      },
      credentialStatus: {
        id: `${holderDid}#status-1`,
        type: 'BitstringStatusListEntry',
        statusListCredential: 'https://example.org/status',
        statusListIndex: '0',
      },
    };

    const signOpts: SignOptions = {
      algorithm: 'ES256',
      header: { kid: 'key-1', alg: 'ES256' },
    };

    return jwt.sign(
      {
        vc: vcBody,
        iss: holderDid,
        iat: nowSec,
        nbf: nowSec,
        exp: opts?.exp ?? nowSec + 3600,
      },
      holderKeys.privateKey,
      signOpts
    );
  }

  function buildVpJwt(vcJwt: string) {
    const nowSec = Math.floor(Date.now() / 1000);
    const vpInner = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiablePresentation'],
      holder: agentDid,
      verifiableCredential: [vcJwt],
    };

    const signOpts: SignOptions = {
      algorithm: 'ES256',
      header: { kid: 'key-1', alg: 'ES256' },
    };

    return jwt.sign(
      {
        vp: vpInner,
        iss: agentDid,
        iat: nowSec,
        exp: nowSec + 3600,
      },
      agentKeys.privateKey,
      signOpts
    );
  }

  it('accepts a valid JWT VP with JWT I2H2A credential (mocked DID + status)', async () => {
    const vpJwt = buildVpJwt(buildVcJwt());
    const res = await verifyI2H2AVP(vpJwt, { skipStatusCheck: true });

    expect(res.valid).toBe(true);
    expect(res.claims).toMatchObject({
      agentDid,
      holderDid,
      scope: { mcpServers: ['allowed-server'], taskType: 'read' },
    });
    expect(res.claims?.authorization).toMatchObject({
      delegationDepth: 0,
      parentCredential: null,
    });
  });

  it('rejects an invalid VP JWT signature', async () => {
    let bad: string = buildVpJwt(buildVcJwt());
    bad = `${bad.slice(0, -4)}XXXX`;

    const res = await verifyI2H2AVP(bad, { skipStatusCheck: true });
    expect(res.valid).toBe(false);
    expect(res.error).toBe('VP signature verification failed');
  });

  it('rejects an expired I2H2A credential', async () => {
    const nowSec = Math.floor(Date.now() / 1000);
    const vpJwt = buildVpJwt(buildVcJwt({ exp: nowSec - 60 }));
    const res = await verifyI2H2AVP(vpJwt, { skipStatusCheck: true });

    expect(res.valid).toBe(false);
    expect(res.error).toBe('I2H2A credential expired');
  });

  it('rejects a revoked credential when status list reports revoked', async () => {
    mockedStatus.mockResolvedValueOnce(false);
    const vpJwt = buildVpJwt(buildVcJwt());
    const res = await verifyI2H2AVP(vpJwt, { skipStatusCheck: false });

    expect(mockedStatus).toHaveBeenCalled();
    expect(res.valid).toBe(false);
    expect(res.error).toBe('I2H2A credential revoked');
  });

  it('rejects when delegation scope does not match request options', async () => {
    const vpJwt = buildVpJwt(buildVcJwt());
    const res = await verifyI2H2AVP(vpJwt, {
      skipStatusCheck: true,
      mcpServerId: 'other-server',
      taskType: 'read',
    });

    expect(res.valid).toBe(false);
    expect(res.error).toBe('Delegation scope does not match request');
  });

  it('rejects when credentialSubject.authorization is missing', async () => {
    const vpJwt = buildVpJwt(buildVcJwt({ authorization: undefined }));
    const res = await verifyI2H2AVP(vpJwt, { skipStatusCheck: true });

    expect(res.valid).toBe(false);
    expect(res.error).toBe('credentialSubject.authorization is required');
  });

  it('rejects when credentialSubject.delegatedBy is missing', async () => {
    const vpJwt = buildVpJwt(buildVcJwt({ delegatedBy: '' }));
    const res = await verifyI2H2AVP(vpJwt, { skipStatusCheck: true });

    expect(res.valid).toBe(false);
    expect(res.error).toBe('credentialSubject.delegatedBy is required');
  });
});
