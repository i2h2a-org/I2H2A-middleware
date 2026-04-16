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

### `resolveDidDocument(did: string, resolverUrl?: string): Promise<DIDDocument>`

Resolves a DID to a DID document. Supports `did:key` (resolved locally, no network call) and any DID method resolvable via a W3C Universal Resolver endpoint. The resolver URL is passed as an optional per-call argument `resolverUrl`, defaulting to the universal resolver fallback.

### `checkCredentialStatus(credential: VerifiableCredential): Promise<boolean>`

Checks credential status against the status list referenced in `credentialStatus`. Returns `true` if active (not revoked). Decodes a base64-encoded `encodedList` and checks the revocation bit at the given index.

## DID resolution

`did:key` is resolved locally per the [did:key method spec](https://w3c-ccg.github.io/did-method-key/). All other DID methods including `did:cheqd`, `did:web`, and any W3C-compliant method are resolved via a [W3C Universal Resolver](https://dev.uniresolver.io) endpoint.

The resolver URL defaults to `https://dev.uniresolver.io/1.0/identifiers/`. To use a different resolver, pass `resolverUrl` in the options:

```typescript
const result = await verifyI2H2AVP(vp, {
  mcpServerId: 'your-mcp-server-id',
  taskType: 'read-only',
  resolverUrl: 'https://your-resolver.example.com/1.0/identifiers/',
});
```

## I2H2A specification

[https://github.com/UltraQuamfy/I2H2A-spec](https://github.com/UltraQuamfy/I2H2A-spec)

## License

MIT