# @i2h2a/mcp-middleware

Reference implementation of I2H2A VP verification middleware for MCP servers and other verifiers.

## Installation

```bash
npm install @i2h2a/mcp-middleware
```

## Quick start

```typescript
import { verifyI2H2AVP } from '@i2h2a/mcp-middleware';
import type { VerifiablePresentation } from '@i2h2a/mcp-middleware';

async function gate(vp: VerifiablePresentation) {
  const result = await verifyI2H2AVP(vp, {
    mcpServerId: 'your-mcp-server-id',
    taskType: 'read-only',
  });

  if (!result.valid) {
    throw new Error(result.error ?? 'Verification failed');
  }

  return result.claims;
}
```

## API reference

### `verifyI2H2AVP(vp, options?)`

Verifies a Verifiable Presentation containing an I2H2A credential. Returns `{ valid: boolean, error?: string, claims?: I2H2AClaims }`.

### `resolveDidDocument(did: string): Promise<DIDDocument>`

Resolves a DID to a DID document. Supports `did:key` (resolved locally, no network call) and any DID method resolvable via a W3C Universal Resolver endpoint, configurable via the `I2H2A_UNIVERSAL_RESOLVER_URL` environment variable.

### `checkCredentialStatus(credential: VerifiableCredential): Promise<boolean>`

Checks credential status against the status list referenced in `credentialStatus`. Returns `true` if active (not revoked). Supports [W3C Bitstring Status List](https://www.w3.org/TR/vc-bitstring-status-list/) and [Status List 2021](https://www.w3.org/community/reports/credentials/CG-FINAL-vc-status-list-2021-20230102/).

## DID resolution

`did:key` is resolved locally per the [did:key method spec](https://w3c-ccg.github.io/did-method-key/). All other DID methods are resolved via a configurable W3C Universal Resolver endpoint:

```bash
I2H2A_UNIVERSAL_RESOLVER_URL=https://dev.uniresolver.io
```

If `I2H2A_UNIVERSAL_RESOLVER_URL` is not set, resolution of non-`did:key` DIDs will fail with a descriptive error.

## I2H2A specification

[https://github.com/UltraQuamfy/I2H2A-spec](https://github.com/UltraQuamfy/I2H2A-spec)

## License

MIT