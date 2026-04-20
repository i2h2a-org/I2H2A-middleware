# @rotavera/mcp-middleware

Reference implementation of I2H2A SD-JWT+KB verification middleware for MCP servers and other verifiers.

Implements the [I2H2A v0.2 specification](https://github.com/UltraQuamfy/I2H2A-spec/blob/main/I2H2A-v0.2-draft.md): SD-JWT VC format (RFC 9901), ES256/P-256 signatures, KB-JWT holder binding.

## Installation

```
npm install @rotavera/mcp-middleware
```

## Quick start

```typescript
import { verifyI2H2APresentation } from '@rotavera/mcp-middleware';

async function gate(sdJwtKb: string, nonce: string) {
  const result = await verifyI2H2APresentation(sdJwtKb, {
    mcpServerId: 'your-mcp-server-id',
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
- `options.mcpServerId: string` — verifier audience identifier; must match `aud` in KB-JWT
- `options.nonce: string` — challenge nonce issued by verifier; must match `nonce` in KB-JWT
- `options.resolverUrl?: string` — optional DID resolver URL override

**Returns:** `{ valid: boolean, error?: string, claims?: I2H2AClaims }`

**Verification steps performed:**
1. Parse SD-JWT+KB (issuer JWT, disclosures, KB-JWT)
2. Verify issuer ES256 signature (P-256, `JsonWebKey2020` verification method)
3. Verify `vct` claim equals `"https://rotavera.io/credentials/I2H2A"`
4. Verify all disclosure hashes against `_sd` array
5. Verify KB-JWT ES256 signature against `cnf.jwk` (agent P-256 public key)
6. Verify KB-JWT `aud`, `nonce`, and `sd_hash` binding
7. Check temporal validity (`nbf`, `exp`)
8. Check Bitstring Status List revocation status (credential status URLs from the VC)
9. Enforce delegation scope (`scope.mcpServers`, `scope.taskType`)
10. Assert `delegationDepth === 0` and `parentCredential === null`

### `resolveDidDocument(did, resolverUrl?)`

Resolves a DID to a DID document. `did:key` is resolved locally. All other methods are resolved via the W3C Universal Resolver endpoint (default: `https://dev.uniresolver.io/1.0/identifiers/`), subject to what your chosen resolver deployment supports.

### `checkCredentialStatus(credentialStatus)`

Checks Bitstring Status List revocation status for the given `credentialStatus` object. Returns `true` if active (not revoked).

## DID resolution

- `did:key` — resolved locally, no network call
- All other methods — resolved via configurable W3C Universal Resolver endpoint (informative example: a public dev instance may use `https://dev.uniresolver.io/1.0/identifiers/` as the base URL)

## Credential format

This middleware verifies **SD-JWT VC** credentials (RFC 9901) with **ES256/P-256** signatures only. SD-JWT VC format (v0.1) is not supported in v0.2+.

## I2H2A specification

https://github.com/UltraQuamfy/I2H2A-spec

## License

MIT