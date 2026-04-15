import fetch from 'node-fetch';
import { checkCredentialStatus } from '../src/check-status';
import type { CredentialStatus, I2H2ACredential } from '../src/types';

jest.mock('node-fetch', () => jest.fn());

const mockedFetch = fetch as unknown as jest.MockedFunction<typeof fetch>;

function makeCredential(statusOverride?: Partial<CredentialStatus>): I2H2ACredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential', 'I2H2A'],
    issuer: 'did:example:issuer',
    credentialSubject: {
      id: 'did:example:agent',
      scope: { mcpServers: ['mcp-a'], taskType: 'read-only' },
      delegationDepth: 0,
      parentCredential: null,
    },
    credentialStatus: {
      id: 'https://example.com/status/1#0',
      type: 'StatusList2021Entry',
      statusListCredential: 'https://example.com/status/1',
      statusListIndex: '0',
      ...(statusOverride ?? {}),
    },
  };
}

function mockFetchJson(ok: boolean, status: number, body: unknown): void {
  mockedFetch.mockResolvedValue({
    ok,
    status,
    json: async () => body,
  } as unknown as Awaited<ReturnType<typeof fetch>>);
}

describe('checkCredentialStatus', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('returns true when status bit is 0 (active credential)', async () => {
    // 0x00 -> "AA==", bit 0 is 0 => active
    mockFetchJson(true, 200, { credentialSubject: { encodedList: 'AA==' } });

    const result = await checkCredentialStatus(makeCredential({ statusListIndex: '0' }));

    expect(result).toBe(true);
    expect(mockedFetch).toHaveBeenCalledWith('https://example.com/status/1', {
      headers: { Accept: 'application/json' },
    });
  });

  it('returns false when status bit is 1 (revoked credential)', async () => {
    // 0x80 -> "gA==", bit 0 is 1 => revoked
    mockFetchJson(true, 200, { credentialSubject: { encodedList: 'gA==' } });

    const result = await checkCredentialStatus(makeCredential({ statusListIndex: '0' }));

    expect(result).toBe(false);
  });

  it('throws when credentialStatus is missing', async () => {
    const credential = {
      ...makeCredential(),
      credentialStatus: undefined,
    } as unknown as I2H2ACredential;

    await expect(checkCredentialStatus(credential)).rejects.toThrow(
      'credentialStatus is missing; cannot check revocation status'
    );
  });

  it('throws when statusListCredential URL is missing', async () => {
    await expect(
      checkCredentialStatus(makeCredential({ statusListCredential: undefined }))
    ).rejects.toThrow('credentialStatus.statusListCredential URL is required');
  });

  it.each([
    ['negative', -1],
    ['NaN', Number.NaN],
    ['non-numeric string', 'abc'],
  ])('throws when statusListIndex is invalid (%s)', async (_label, badIndex) => {
    await expect(
      checkCredentialStatus(makeCredential({ statusListIndex: badIndex as string | number }))
    ).rejects.toThrow('credentialStatus.statusListIndex must be a non-negative integer');
  });

  it('throws when statusListIndex is out of range for the encoded bitstring', async () => {
    // one byte only -> indexes 0..7 are valid; index 8 is out of range
    mockFetchJson(true, 200, { credentialSubject: { encodedList: 'AA==' } });

    await expect(
      checkCredentialStatus(makeCredential({ statusListIndex: '8' }))
    ).rejects.toThrow('statusListIndex out of range for encoded status list');
  });

  it('throws when the status list fetch returns non-200', async () => {
    mockFetchJson(false, 503, {});

    await expect(checkCredentialStatus(makeCredential())).rejects.toThrow(
      'Status list could not be fetched (503): https://example.com/status/1'
    );
  });

  it('throws when the status list document is missing encodedList', async () => {
    mockFetchJson(true, 200, { credentialSubject: {} });

    await expect(checkCredentialStatus(makeCredential())).rejects.toThrow(
      'Status list document missing encodedList'
    );
  });
});
