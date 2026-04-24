import type { I2H2ADisclosedClaims } from './types';

export function validateDelegationScope(
  claims: I2H2ADisclosedClaims,
  serverId: string
): boolean {
  // Prefer scope.services; support scope.mcpServers for backward compatibility.
  const allowedServers = claims['scope.services'] ?? claims['scope.mcpServers'];

  if (!Array.isArray(allowedServers) || allowedServers.length === 0) {
    return false;
  }

  for (const server of allowedServers) {
    if (typeof server !== 'string' || server.trim() === '') {
      return false;
    }
  }

  const normalizedId = serverId.trim();
  return allowedServers.some((s) => s.trim() === normalizedId);
}
