/**
 * Example: Express middleware that verifies an I2H2A presentation
 * on protected routes.
 *
 * Install peer dependency: `npm install express`
 *
 * ```ts
 * import express from 'express';
 * import { verifyI2H2APresentation } from '@i2h2a/mcp-middleware';
 *
 * const app = express();
 * app.use(express.json());
 *
 * app.post('/mcp', async (req, res, next) => {
 *   const sdJwtKb = req.body?.sdJwtKb;
 *   const result = await verifyI2H2APresentation(sdJwtKb, {
 *     mcpServerId: process.env.MCP_SERVER_ID,
 *     taskType: req.body?.taskType,
 *   });
 *   if (!result.valid) {
 *     return res.status(401).json({ error: result.error ?? 'presentation verification failed' });
 *   }
 *   (req as any).i2h2aClaims = result.claims;
 *   next();
 * });
 * ```
 */

export {};
