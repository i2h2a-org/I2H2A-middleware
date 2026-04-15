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
4. Resolves both DIDs and obtains verification key material
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

**did:key resolution** — self-resolving, no external resolver required. The public key is derived directly from the DID string.

**cheqd credential verification** — calls cheqd Studio `/credential/verify` to verify the I2H2A JWT-VC signature and revocation status.

> **Testnet note:** On cheqd testnet, `policies.credentialStatus` always returns `false` — known limitation. The middleware checks `data.revoked === true` only. Restore full policy check on mainnet migration.

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

## Production deployment

Call this middleware at session initiation — once per session, not per request. Present the VP as a Bearer token in the MCP OAuth 2.1 slot.

For deployments where local `file:` dependencies cause build issues (e.g. Railway), inline the verification logic directly from source rather than importing the package. This repo is the reference implementation.

---

## Reference deployment

Live on cheqd testnet:

- Platform: [ultraquamfy.netlify.app](https://ultraquamfy.netlify.app)
- MCP shim: [ultraquamfy-production.up.railway.app](https://ultraquamfy-production.up.railway.app)
- Issuer DID: `did:cheqd:testnet:ec6a1292-eb42-4754-bef3-9c3e95c32212`

---

## License

MIT