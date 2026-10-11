import { describe, it, expect, vi, beforeEach } from 'vitest';
import { computeClientBucketToken, getCurrentHourTs } from '../telemetry';

describe('Telemetry', () => {
  beforeEach(() => {
    vi.resetModules();
  });

  it('generates consistent bucket tokens for same hour', () => {
    const ts = getCurrentHourTs();
    const token1 = computeClientBucketToken(ts);
    const token2 = computeClientBucketToken(ts);
    expect(token1).toEqual(token2);
    expect(token1.length).toBe(64); // 256 bits = 64 hex chars
  });
});
