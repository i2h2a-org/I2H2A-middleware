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

describe('integration (end-to-end VP verification)', () => {
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
      if (did === holderDid) return makeDidDoc(holderDid, holderPub);
      if (did === agentDid) return makeDidDoc(agentDid, agentPub);
      throw new Error(`unexpected DID: ${did}`);
    });

    mockedStatus.mockResolvedValue(true);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  function buildVcJwt(opts?: {
    exp?: number;
    types?: string[];
    delegationDepth?: number;
    parentCredential?: string | null;
    scopeServer?: string;
    scopeTask?: string;
  }): string {
    const nowSec = Math.floor(Date.now() / 1000);
    const vcBody = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: opts?.types ?? ['VerifiableCredential', 'I2H2A'],
      issuer: holderDid,
      credentialSubject: {
        id: agentDid,
        scope: {
          mcpServers: [opts?.scopeServer ?? 'allowed-server'],
          taskType: opts?.scopeTask ?? 'read-only',
        },
        delegationDepth: opts?.delegationDepth ?? 0,
        parentCredential: opts?.parentCredential ?? null,
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

  function buildVpJwt(
    vcPayload: unknown,
    opts?: { includeVcArray?: boolean; signWithWrongKey?: boolean }
  ): string {
    const nowSec = Math.floor(Date.now() / 1000);
    const vpInner: Record<string, unknown> = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiablePresentation'],
      holder: agentDid,
    };
    if (opts?.includeVcArray !== false) {
      vpInner.verifiableCredential = [vcPayload];
    }

    const signOpts: SignOptions = {
      algorithm: 'ES256',
      header: { kid: 'key-1', alg: 'ES256' },
    };

    const signerKey = opts?.signWithWrongKey
      ? crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' as const }).privateKey
      : agentKeys.privateKey;

    return jwt.sign(
      {
        vp: vpInner,
        iss: agentDid,
        iat: nowSec,
        exp: nowSec + 3600,
      },
      signerKey,
      signOpts
    );
  }

  it('valid VP with matching mcpServerId and taskType returns valid=true with correct claims', async () => {
    const vpJwt = buildVpJwt(buildVcJwt());
    const res = await verifyI2H2AVP(vpJwt, {
      mcpServerId: 'allowed-server',
      taskType: 'read-only',
    });

    expect(res.valid).toBe(true);
    expect(res.claims).toMatchObject({
      agentDid,
      holderDid,
      scope: { mcpServers: ['allowed-server'], taskType: 'read-only' },
      authorization: { delegationDepth: 0, parentCredential: null },
    });
  });

  it('valid VP with no scope options passed returns valid=true', async () => {
    const vpJwt = buildVpJwt(buildVcJwt());
    const res = await verifyI2H2AVP(vpJwt);

    expect(res.valid).toBe(true);
  });

  it('VP with mismatched mcpServerId returns valid=false', async () => {
    const vpJwt = buildVpJwt(buildVcJwt());
    const res = await verifyI2H2AVP(vpJwt, {
      mcpServerId: 'different-server',
      taskType: 'read-only',
    });

    expect(res.valid).toBe(false);
    expect(res.error).toBe('Delegation scope does not match request');
  });

  it('VP with mismatched taskType returns valid=false', async () => {
    const vpJwt = buildVpJwt(buildVcJwt());
    const res = await verifyI2H2AVP(vpJwt, {
      mcpServerId: 'allowed-server',
      taskType: 'write',
    });

    expect(res.valid).toBe(false);
    expect(res.error).toBe('Delegation scope does not match request');
  });

  it('VP with revoked credential returns valid=false', async () => {
    mockedStatus.mockResolvedValueOnce(false);
    const vpJwt = buildVpJwt(buildVcJwt());
    const res = await verifyI2H2AVP(vpJwt);

    expect(res.valid).toBe(false);
    expect(res.error).toBe('I2H2A credential revoked');
  });

  it('VP with expired credential returns valid=false', async () => {
    const nowSec = Math.floor(Date.now() / 1000);
    const vpJwt = buildVpJwt(buildVcJwt({ exp: nowSec - 60 }));
    const res = await verifyI2H2AVP(vpJwt);

    expect(res.valid).toBe(false);
    expect(res.error).toBe('I2H2A credential expired');
  });

  it('VP with invalid signature returns valid=false', async () => {
    const vpJwt = buildVpJwt(buildVcJwt(), { signWithWrongKey: true });
    const res = await verifyI2H2AVP(vpJwt);

    expect(res.valid).toBe(false);
    expect(res.error).toBe('VP signature verification failed');
  });

  it('VP missing verifiableCredential array returns valid=false', async () => {
    const vpJwt = buildVpJwt(buildVcJwt(), { includeVcArray: false });
    const res = await verifyI2H2AVP(vpJwt);

    expect(res.valid).toBe(false);
    expect(res.error).toBe('VP must contain verifiableCredential array');
  });

  it('VP with wrong credential type (not I2H2A) returns valid=false', async () => {
    const vpJwt = buildVpJwt(buildVcJwt({ types: ['VerifiableCredential', 'OtherType'] }));
    const res = await verifyI2H2AVP(vpJwt);

    expect(res.valid).toBe(false);
    expect(res.error).toBe('No I2H2A credential in VP');
  });

  it('VP with delegationDepth != 0 returns valid=false', async () => {
    const vpJwt = buildVpJwt(buildVcJwt({ delegationDepth: 1 }));
    const res = await verifyI2H2AVP(vpJwt);

    expect(res.valid).toBe(false);
    expect(res.error).toBe('Invalid delegation depth (must be 0 for V1)');
  });

  it('VP with parentCredential != null returns valid=false', async () => {
    const vpJwt = buildVpJwt(buildVcJwt({ parentCredential: 'urn:vc:parent:1' }));
    const res = await verifyI2H2AVP(vpJwt);

    expect(res.valid).toBe(false);
    expect(res.error).toBe('Parent credential must be null for H2A (V1)');
  });
});
