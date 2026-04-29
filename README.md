# @i2h2a/verification-sdk

Reference implementation of I2H2A SD-JWT+KB verification for any integration point and other verifiers.

Implements the **SD-JWT VC** profile from **[I2H2A v0.2](https://github.com/i2h2a-org/I2H2A-spec/blob/main/I2H2A-v0.2-draft.md)** (RFC 9901, ES256/P-256, KB-JWT holder binding). For the overarching **v0.3** protocol narrative, see **[I2H2A-v0.3-draft.md](https://github.com/i2h2a-org/I2H2A-spec/blob/main/I2H2A-v0.3-draft.md)**.

## Installation

```
npm install @i2h2a/verification-sdk
```

## Use Cases

- MCP servers (import and mount in Express routes)
- Shopify apps (plugin verification logic)
- Payment gateways (verify mandate before processing)
- API middleware (drop into REST/GraphQL endpoints)

## Quick start

```typescript
import { verifyI2H2APresentation } from '@i2h2a/verification-sdk';

async function gate(sdJwtKb: string, nonce: string) {
  const result = await verifyI2H2APresentation(sdJwtKb, {
    serverId: 'your-service-id',
    nonce,
  });

  if (!result.valid) {
    throw new Error(result.error ?? 'Verification failed');
  }

  return result.claims;
}
```

The `sdJwtKb` parameter is an SD-JWT+KB string in the format:
```
~~~...~
```

## API reference

### `verifyI2H2APresentation(sdJwtKb, options)`

Verifies an SD-JWT+KB presentation containing an I2H2A credential.

**Parameters:**
- `sdJwtKb: string` — SD-JWT+KB compact serialisation
- `options.serverId: string` — verifier audience identifier; must match `aud` in KB-JWT
- `options.mcpServerId?: string` — backward compatibility alias for `serverId`
- `options.nonce: string` — challenge nonce issued by verifier; must match `nonce` in KB-JWT
- `options.resolverUrl?: string` — optional DID resolver URL override

**Returns:** `{ valid: boolean, error?: string, claims?: I2H2AClaims }`

**Verification steps performed:**
1. Parse SD-JWT+KB (issuer JWT, disclosures, KB-JWT)
2. Verify issuer ES256 signature (P-256, `JsonWebKey2020` verification method)
3. Verify `vct` claim equals `"https://i2h2a.org/credentials/I2H2A"`
4. Verify all disclosure hashes against `_sd` array
5. Verify KB-JWT ES256 signature against `cnf.jwk` (agent P-256 public key)
6. Verify KB-JWT `aud`, `nonce`, and `sd_hash` binding
7. Check temporal validity (`nbf`, `exp`)
8. Check Bitstring Status List revocation status (credential status URLs from the VC)
9. Enforce delegation scope (`scope.services`, `scope.taskType`) with fallback to `scope.mcpServers`
10. Assert `delegationDepth === 0` and `parentCredential === null`

### `resolveDidDocument(did, resolverUrl?)`

Resolves a DID to a DID document. `did:key` is resolved locally. All other methods are resolved via the W3C Universal Resolver endpoint (default: `https://dev.uniresolver.io/1.0/identifiers/`), subject to what your chosen resolver deployment supports.

### `checkCredentialStatus(credentialStatus)`

Checks Bitstring Status List revocation status for the given `credentialStatus` object. Returns `true` if active (not revoked).

## DID resolution

- `did:key` — resolved locally, no network call
- All other methods — resolved via configurable W3C Universal Resolver endpoint (informative example: a public dev instance may use `https://dev.uniresolver.io/1.0/identifiers/` as the base URL)

## Credential format

This SDK verifies **SD-JWT VC** credentials (RFC 9901) with **ES256/P-256** signatures only—the **v0.2** interoperable credential shape. Older ad-hoc payloads (informally referred to alongside **v0.1** lineage) outside that profile are not supported.

## I2H2A specification

https://github.com/i2h2a-org/I2H2A-spec

## License

MIT
