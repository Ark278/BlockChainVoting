import { hmac } from '@noble/hashes/hmac.js';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex } from '@noble/hashes/utils.js';

// 1. In-memory ephemeral secret (32 bytes)
let clientEphemeralSecret: Uint8Array | null = null;

function getEphemeralSecret(): Uint8Array {
  if (!clientEphemeralSecret) {
    clientEphemeralSecret = new Uint8Array(32);
    crypto.getRandomValues(clientEphemeralSecret as any);
  }
  return clientEphemeralSecret;
}

/**
 * Encodes a 64-bit unsigned integer in big-endian format.
 * @param value Unix timestamp in seconds
 */
function uint64_be(value: number): Uint8Array {
  const buffer = new ArrayBuffer(8);
  const view = new DataView(buffer);
  view.setBigUint64(0, BigInt(Math.floor(value)), false);
  return new Uint8Array(buffer);
}

/**
 * Computes client_bucket_token = HMAC-SHA3-256(client_ephemeral_secret, uint64_be(bucket_start))
 * @param bucketStart Unix timestamp (seconds)
 */
export function computeClientBucketToken(bucketStart: number): string {
  const secret = getEphemeralSecret();
  const msg = uint64_be(bucketStart);
  
  const tokenBytes = hmac(sha3_256, secret, msg);
  return bytesToHex(tokenBytes);
}

/**
 * Gets the current hour boundary in UTC seconds
 */
export function getCurrentHourTs(): number {
  const now = Math.floor(Date.now() / 1000);
  return Math.floor(now / 3600) * 3600;
}
