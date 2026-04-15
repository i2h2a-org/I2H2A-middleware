# @i2h2a/mcp-middleware

**OID4VP verification middleware for I2H2A delegation credentials**

Drop-in npm middleware that verifies I2H2A Verifiable Presentations at MCP session initiation. Any MCP server operator can add I2H2A verification with one import and a few lines of code.

→ Spec: [github.com/UltraQuamfy/I2H2A-spec](https://github.com/UltraQuamfy/I2H2A-spec)

---

## What it does

When an AI agent presents a VP to your MCP server, this middleware:

1. Parses the VP and extracts the I2H2A credential
2. Verifies the VP proof is signed by the agent's `did:key`
3. Verifies the issuer's signature on the I2H2A credential
4. Resolves both DIDs using a W3C-compliant universal resolver
5. Checks temporal validity (`issuanceDate` / `expirationDate`)
6. Checks revocation status via the credential's status list
7. Validates delegation scope (`mcpServers`, `taskType`) against the request
8. Checks `delegationDepth == 0` (v1 terminal delegation)
9. Checks `parentCredential == null` (v1)

Returns `{ valid: true }` or `{ valid: false, error: string }`.

---

## Install

```bash
npm install @i2h2a/mcp-middleware
```

---

## Quick start

```typescript
import { verifyI2H2AVP } from '@i2h2a/mcp-middleware';

const result = await verifyI2H2AVP({
  vpJwt: request.headers.authorization.replace('Bearer ', ''),
  requestContext: {
    mcpServerId: 'your-mcp-server-id',
    taskType: 'product_search'
  }
});

if (!result.valid) {
  return reply.status(403).send({ error: result.error });
}

// Proceed with authorised request
```

---

## Verification pipeline

The middleware implements the full 9-step normative algorithm from [I2H2A-v1.0.md Section 4](https://github.com/UltraQuamfy/I2H2A-spec/blob/main/I2H2A-v1.0.md#4-verification-algorithm).

**DID resolution** — the middleware resolves issuer and agent DIDs using a W3C-compliant universal resolver. The resolver endpoint is configurable via `I2H2A_UNIVERSAL_RESOLVER_URL`. `did:key` is self-resolving and requires no external call.

**Credential signature verification** — the middleware verifies the JWT-VC signature using public key material from the resolved DID document. Any DID method supported by your configured resolver works — `did:cheqd`, `did:web`, `did:ion`, `did:key`, or any W3C-conformant method.

**Revocation status** — checked against the `credentialStatus` field in the credential using the referenced status list. Compatible with Status List 2021 and Bitstring Status List.

---

## VP format

The agent constructs a W3C VP 2.0 JWT signed with its ephemeral `did:key` (Ed25519 / EdDSA). The VP wraps the I2H2A JWT-VC as the `verifiableCredential` claim.

```json
{
  "vp": {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "type": ["VerifiablePresentation"],
    "holder": "did:key:z6Mk...",
    "verifiableCredential": ["<I2H2A JWT-VC>"]
  }
}
```

The VP JWT is signed by the agent's `did:key`. The embedded I2H2A JWT-VC is signed by the human holder's DID.

---

## Configuration

| Environment variable | Description |
|---|---|
| `I2H2A_UNIVERSAL_RESOLVER_URL` | W3C universal resolver endpoint (e.g. `https://dev.uniresolver.io`) |

`did:key` requires no resolver configuration — it is self-resolving per the W3C DID Core spec.

---

## DID method support

The middleware is DID-method agnostic. Any method resolvable via your configured universal resolver is supported. `did:key` is resolved locally with no network call required.

---

## Production deployment

Call this middleware at session initiation — once per session, not per request. Present the VP as a Bearer token in the MCP OAuth 2.1 slot.

---

## License

MIT