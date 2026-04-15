import fetch from 'node-fetch';
import { resolveDidDocument } from '../src/resolve-did';

jest.mock('node-fetch', () => jest.fn());

const mockedFetch = fetch as unknown as jest.MockedFunction<typeof fetch>;

function mockResolverJson(ok: boolean, status: number, body: unknown): void {
  mockedFetch.mockResolvedValue({
    ok,
    status,
    json: async () => body,
  } as unknown as Awaited<ReturnType<typeof fetch>>);
}

describe('resolveDidDocument', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('resolves did:key locally without any network call', async () => {
    const did = 'did:key:z6MkiboHoaMf4yS2Nn81WhnWL7Khz16WYs7MNNUFW5kSNDUz';

    const doc = await resolveDidDocument(did);

    expect(doc.id).toBe(did);
    expect(mockedFetch).not.toHaveBeenCalled();
  });

  it('returns correct verification method for a valid did:key (Ed25519, multicodec 0xed01)', async () => {
    const did = 'did:key:z6MkiboHoaMf4yS2Nn81WhnWL7Khz16WYs7MNNUFW5kSNDUz';

    const doc = await resolveDidDocument(did);
    const vm = doc.verificationMethod?.[0];

    expect(vm).toBeDefined();
    expect(vm?.type).toBe('Ed25519VerificationKey2020');
    expect(vm?.controller).toBe(did);
    expect(vm?.id).toBe(`${did}#z6MkiboHoaMf4yS2Nn81WhnWL7Khz16WYs7MNNUFW5kSNDUz`);
    expect(vm?.publicKeyJwk).toMatchObject({
      kty: 'OKP',
      crv: 'Ed25519',
    });
    expect(typeof vm?.publicKeyJwk?.x).toBe('string');
    expect((vm?.publicKeyJwk?.x as string).length).toBeGreaterThan(0);
  });

  it.each([
    '',
    'example:123',
    'did:',
  ])('throws for an invalid DID string: %p', async (did) => {
    await expect(resolveDidDocument(did)).rejects.toThrow();
  });

  it('throws for an unsupported DID method (did:example)', async () => {
    await expect(resolveDidDocument('did:example:abc')).rejects.toThrow(
      'Unsupported DID method for resolver: example'
    );
  });

  it('throws when universal resolver returns non-200 for did:web', async () => {
    mockResolverJson(false, 503, {});

    await expect(resolveDidDocument('did:web:example.com')).rejects.toThrow(
      'DID resolution failed (503): did:web:example.com'
    );
  });

  it('throws when universal resolver returns no didDocument for did:web', async () => {
    mockResolverJson(true, 200, { didResolutionMetadata: {} });

    await expect(resolveDidDocument('did:web:example.com')).rejects.toThrow(
      'DID resolution returned no didDocument for did:web:example.com'
    );
  });

  it('resolves did:web via universal resolver and returns didDocument', async () => {
    const webDid = 'did:web:example.com';
    const expected = {
      id: webDid,
      verificationMethod: [
        {
          id: `${webDid}#key-1`,
          type: 'JsonWebKey2020',
          controller: webDid,
          publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' },
        },
      ],
    };
    mockResolverJson(true, 200, { didDocument: expected });

    const doc = await resolveDidDocument(webDid);

    expect(doc).toEqual(expected);
    expect(mockedFetch).toHaveBeenCalledWith(
      'https://dev.uniresolver.io/1.0/identifiers/did%3Aweb%3Aexample.com',
      { headers: { Accept: 'application/did+json,application/json' } }
    );
  });

  it('resolves did:cheqd via universal resolver and returns didDocument', async () => {
    const cheqdDid = 'did:cheqd:testnet:abc-123';
    const expected = {
      id: cheqdDid,
      verificationMethod: [
        {
          id: `${cheqdDid}#key-1`,
          type: 'Ed25519VerificationKey2020',
          controller: cheqdDid,
          publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'abc' },
        },
      ],
    };
    mockResolverJson(true, 200, { didDocument: expected });

    const doc = await resolveDidDocument(cheqdDid);

    expect(doc).toEqual(expected);
    expect(mockedFetch).toHaveBeenCalledWith(
      'https://dev.uniresolver.io/1.0/identifiers/did%3Acheqd%3Atestnet%3Aabc-123',
      { headers: { Accept: 'application/did+json,application/json' } }
    );
  });

  it('strips fragment from DID before resolving', async () => {
    const didWithFragment = 'did:key:z6MkiboHoaMf4yS2Nn81WhnWL7Khz16WYs7MNNUFW5kSNDUz#key-1';

    const doc = await resolveDidDocument(didWithFragment);

    expect(doc.id).toBe('did:key:z6MkiboHoaMf4yS2Nn81WhnWL7Khz16WYs7MNNUFW5kSNDUz');
    expect(mockedFetch).not.toHaveBeenCalled();
  });
});
