# @i2h2a/mcp-middleware

Reference implementation of OID4VP verification middleware for I2H2A delegation credentials.

## Installation

```bash
npm install @i2h2a/mcp-middleware
```

## DID Resolution

The middleware supports the following DID methods:

- **did:key** - Resolved locally (self-resolving, no network call)
- **did:web** - Resolved via universal resolver
- **did:cheqd** - Currently uses cheqd's native resolver (temporary)

**Note:** The cheqd-specific resolver is a temporary convenience feature
while universal resolvers don't properly support did:cheqd. This will be
replaced with a configurable universal resolver endpoint before v1.0.

For other DID methods, configure a universal resolver endpoint (coming in v1.0).

## Quick start

```ts
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

Verifies a **Verifiable Presentation** containing an I2H2A credential. Returns `{ valid, error?, claims? }`.

### `resolveDidDocument(did)`

Resolves a **DID** to a **DID document** (e.g. for signature verification keys). Behavior by method is described under [DID Resolution](#did-resolution); **did:web** uses a configurable universal resolver (`I2H2A_UNIVERSAL_RESOLVER_URL`).

### `checkCredentialStatus(credential)`

Checks **credential status** (e.g. status list bitstring) for revocation. Returns `true` if the credential is valid (not revoked).

## I2H2A specification

- [I2H2A specification](https://github.com/UltraQuamfy/I2H2A-spec)

## Known Limitations

- **DID Resolution**: Currently includes cheqd-specific resolver code.
  This will be replaced with a configurable universal resolver before v1.0
  to maintain true platform-agnosticism.

- **Status List Formats**: Currently supports StatusList2021 and
  BitstringStatusList. Other formats may require custom handling.

- **Credential Formats**: Tested with JWT-VC and JSON-LD credentials.
  Other formats (e.g., SD-JWT) may require additional work.

## License

MIT
