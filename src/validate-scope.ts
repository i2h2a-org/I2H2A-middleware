import type { I2H2ADisclosedClaims } from './types';

export function validateDelegationScope(
  claims: I2H2ADisclosedClaims,
  mcpServerId: string
): boolean {
  const allowedServers = claims['scope.mcpServers'];
  if (!Array.isArray(allowedServers) || allowedServers.length === 0) {
    return false;
  }

  return allowedServers.includes(mcpServerId);
}
