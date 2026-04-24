import { describe, expect, it } from '@jest/globals';
import { validateDelegationScope } from '../src/validate-scope';
import type { I2H2ADisclosedClaims } from '../src/types';

describe('validateDelegationScope', () => {
  it('allows when serverId is in scope.services', () => {
    const claims: I2H2ADisclosedClaims = {
      'scope.services': ['server-a', 'server-b'],
    };
    expect(validateDelegationScope(claims, 'server-a')).toBe(true);
  });

  it('denies when serverId is not in scope.services', () => {
    const claims: I2H2ADisclosedClaims = {
      'scope.services': ['server-a', 'server-b'],
    };
    expect(validateDelegationScope(claims, 'server-c')).toBe(false);
  });

  it('denies when scope.services is empty', () => {
    const claims: I2H2ADisclosedClaims = {
      'scope.services': [],
    };
    expect(validateDelegationScope(claims, 'server-a')).toBe(false);
  });

  it('denies when scope.services and scope.mcpServers are missing', () => {
    const claims: I2H2ADisclosedClaims = {};
    expect(validateDelegationScope(claims, 'server-a')).toBe(false);
  });

  it('denies when scope.services contains empty strings', () => {
    const claims: I2H2ADisclosedClaims = {
      'scope.services': ['server-a', '', 'server-b'],
    };
    expect(validateDelegationScope(claims, '')).toBe(false);
  });

  it('denies when scope.services contains non-strings', () => {
    const claims: I2H2ADisclosedClaims = {
      'scope.services': ['server-a', 123 as any, 'server-b'],
    };
    expect(validateDelegationScope(claims, 'server-a')).toBe(false);
  });

  it('handles whitespace trimming', () => {
    const claims: I2H2ADisclosedClaims = {
      'scope.services': [' server-a ', 'server-b'],
    };
    expect(validateDelegationScope(claims, 'server-a')).toBe(true);
    expect(validateDelegationScope(claims, ' server-a ')).toBe(true);
  });

  it('supports backward compatibility with scope.mcpServers', () => {
    const claims: I2H2ADisclosedClaims = {
      'scope.mcpServers': ['legacy-server'],
    };
    expect(validateDelegationScope(claims, 'legacy-server')).toBe(true);
  });
});
