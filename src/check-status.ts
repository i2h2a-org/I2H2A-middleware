import fetch from 'node-fetch';
import { gunzip, inflateRaw } from 'zlib';
import { promisify } from 'util';
import type { CredentialStatusEntry } from './types';

const gunzipAsync = promisify(gunzip);
const inflateRawAsync = promisify(inflateRaw);

async function decodeBitstringBytes(encoded: string): Promise<Buffer> {
  const raw = Buffer.from(encoded, 'base64');

  try {
    return await gunzipAsync(raw);
  } catch {
    // Fall through to raw inflate.
  }

  try {
    return await inflateRawAsync(raw);
  } catch {
    // Fall through to uncompressed bitstring.
  }

  return raw;
}

/**
 * Fetch a status list credential (JSON) and test the bit at `statusListIndex`.
 */
export async function checkCredentialStatus(status: CredentialStatusEntry): Promise<boolean> {
  const listUrl = status.statusListCredential;
  if (!listUrl || typeof listUrl !== 'string') {
    throw new Error('credentialStatus.statusListCredential URL is required');
  }

  const index = status.statusListIndex;
  if (!Number.isFinite(index) || index < 0 || !Number.isInteger(index)) {
    throw new Error('credentialStatus.statusListIndex must be a finite non-negative integer');
  }

  const res = await fetch(listUrl, { headers: { Accept: 'application/json' } });
  if (!res.ok) {
    throw new Error(`Status list could not be fetched (${res.status}): ${listUrl}`);
  }

  const listDoc = (await res.json()) as {
    credentialSubject?: { encodedList?: string };
    encodedList?: string;
  };

  const encoded = listDoc.credentialSubject?.encodedList ?? listDoc.encodedList;

  if (!encoded || typeof encoded !== 'string') {
    throw new Error('Status list document missing encodedList');
  }

  const buf = await decodeBitstringBytes(encoded);
  const byteIndex = Math.floor(index / 8);
  const bitPos = index % 8;

  if (byteIndex >= buf.length) {
    throw new Error('statusListIndex out of range for encoded status list');
  }

  const byte = buf[byteIndex];
  if (byte === undefined) {
    throw new Error('statusListIndex byte is undefined');
  }
  const bit = (byte >> (7 - bitPos)) & 1;

  // Bit convention per W3C Bitstring Status List §7: 0 = active, 1 = revoked.
  return bit === 0;
}
