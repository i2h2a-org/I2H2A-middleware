/**
 * Example: MCP (Model Context Protocol) server wiring — verify I2H2A presentation before
 * handling tool calls so only delegated agents with valid credentials proceed.
 *
 * Pseudocode for a Node MCP server using `@modelcontextprotocol/sdk` or similar:
 *
 * ```ts
 * import { verifyI2H2APresentation } from '@rotavera/verification-sdk';
 *
 * // When the client connects or sends an initial message with a compact presentation:
 * async function onClientPresentation(sdJwtKb: string) {
 *   const out = await verifyI2H2APresentation(sdJwtKb, {
 *     serverId: 'my-service-id',
 *     taskType: 'read-only',
 *   });
 *   if (!out.valid) throw new Error(out.error ?? 'Invalid I2H2A presentation');
 *   return out.claims;
 * }
 * ```
 *
 * Bind `onClientPresentation` to your transport’s authentication or session setup phase.
 */

export {};
