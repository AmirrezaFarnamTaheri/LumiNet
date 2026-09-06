/**
 * C10.1a — incy-link-encoder crypt1 encrypted deep-link share.
 *
 * LumiNet's "share profile" button produces a `luminet://share?d=<crypt1>`
 * URL. The `d` parameter is an AES-256-GCM ciphertext, base64url encoded,
 * containing the profile JSON. The shared key is a SHA-256 derivation of:
 *
 *   1. The profile's `sharePassphrase` (per-profile passphrase), if set.
 *   2. Otherwise, a global app secret from the OS keychain.
 *
 * This module is isomorphic — it runs in the browser (control-ui) and in
 * the daemon (Node, see crypt1.go). The wire format MUST match the Go
 * implementation exactly.
 *
 * ## Wire format
 *
 *   base64url( nonce(12) || ciphertext || authTag(16) )
 *
 * The nonce is generated freshly per encryption. The 32-byte key is
 * derived once via SHA-256 over the passphrase.
 *
 * @module utils/crypt1
 */

const NONCE_LEN = 12;
const TAG_LEN = 16;

/** Result of a [crypt1Encrypt] call. */
export interface Crypt1Payload {
  /** The base64url-encoded payload (nonce + ct + tag). */
  readonly d: string;
  /** Key derivation identifier (which secret was used). */
  readonly kid: string;
  /** Schema version, always `crypt1`. */
  readonly v: 'crypt1';
}

/** Decrypted payload returned by [crypt1Decrypt]. */
export interface Crypt1Plaintext {
  /** The decoded bytes as a UTF-8 string. */
  readonly text: string;
  /** The key derivation identifier that was used. */
  readonly kid: string;
}

/** Convert an ArrayBuffer to a base64url string (no padding). */
export function bytesToBase64Url(bytes: ArrayBuffer | Uint8Array): string {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = '';
  for (let i = 0; i < u8.length; i++) {
    bin += String.fromCharCode(u8[i]!);
  }
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

/** Convert a base64url string to a Uint8Array. */
export function base64UrlToBytes(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  const b64 = (s + pad).replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

/** Constant-time string equality (browser). */
export function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

/** SHA-256 over a UTF-8 string. */
export async function sha256(input: string): Promise<Uint8Array> {
  const data = new TextEncoder().encode(input);
  const buf = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(buf);
}

/** Derive the 32-byte AES-256 key from a passphrase. */
export async function deriveKey(passphrase: string, kid: string): Promise<Uint8Array> {
  return sha256(`${kid}::${passphrase}`);
}

/**
 * Encrypt a UTF-8 string under [passphrase] and return the wire payload.
 *
 * @param plaintext  The UTF-8 string to encrypt.
 * @param passphrase The shared secret (per-profile or app-global).
 * @param kid        Key derivation identifier; recipients use it to look
 *                   up the matching secret. Defaults to `'app'`.
 */
export async function crypt1Encrypt(
  plaintext: string,
  passphrase: string,
  kid: string = 'app',
): Promise<Crypt1Payload> {
  if (!passphrase) {
    throw new Error('crypt1Encrypt: passphrase must not be empty');
  }
  const key = await deriveKey(passphrase, kid);
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key as BufferSource,
    { name: 'AES-GCM' },
    false,
    ['encrypt'],
  );
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
  const data = new TextEncoder().encode(plaintext);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce as BufferSource, tagLength: TAG_LEN * 8 },
      cryptoKey,
      data as BufferSource,
    ),
  );
  const out = new Uint8Array(nonce.length + ct.length);
  out.set(nonce, 0);
  out.set(ct, nonce.length);
  return { d: bytesToBase64Url(out), kid, v: 'crypt1' };
}

/**
 * Decrypt a [Crypt1Payload] under [passphrase]. Throws on MAC failure
 * or malformed input.
 */
export async function crypt1Decrypt(
  payload: Crypt1Payload,
  passphrase: string,
): Promise<Crypt1Plaintext> {
  if (payload.v !== 'crypt1') {
    throw new Error(`crypt1Decrypt: unsupported version ${payload.v}`);
  }
  if (!passphrase) {
    throw new Error('crypt1Decrypt: passphrase must not be empty');
  }
  const key = await deriveKey(passphrase, payload.kid);
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key as BufferSource,
    { name: 'AES-GCM' },
    false,
    ['decrypt'],
  );
  const raw = base64UrlToBytes(payload.d);
  if (raw.length < NONCE_LEN + TAG_LEN) {
    throw new Error('crypt1Decrypt: payload too short');
  }
  const nonce = raw.subarray(0, NONCE_LEN);
  const ct = raw.subarray(NONCE_LEN);
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce as BufferSource, tagLength: TAG_LEN * 8 },
    cryptoKey,
    ct as BufferSource,
  );
  return { text: new TextDecoder().decode(pt), kid: payload.kid };
}

// ---------------------------------------------------------------------------
// Tests (Vitest-style, runnable with `node --import tsx --test crypt1.ts`).
// ---------------------------------------------------------------------------

/**
 * @vitest-environment node
 */
export const __tests = {
  /**
   * Test 1 — round-trip with a known plaintext.
   */
  async roundTrip(): Promise<void> {
    const pt = 'hello, world!';
    const payload = await crypt1Encrypt(pt, 'sekret');
    const out = await crypt1Decrypt(payload, 'sekret');
    if (out.text !== pt) throw new Error(`roundtrip mismatch: ${out.text}`);
  },

  /**
   * Test 2 — wrong passphrase fails.
   */
  async wrongPassphraseFails(): Promise<void> {
    const payload = await crypt1Encrypt('top secret', 'correct');
    let threw = false;
    try {
      await crypt1Decrypt(payload, 'incorrect');
    } catch {
      threw = true;
    }
    if (!threw) throw new Error('decrypt with wrong passphrase must throw');
  },

  /**
   * Test 3 — base64url helpers are inverse.
   */
  async base64RoundTrip(): Promise<void> {
    const original = '???>>>'.repeat(20);
    const enc = new TextEncoder().encode(original);
    const s = bytesToBase64Url(enc);
    const dec = base64UrlToBytes(s);
    const back = new TextDecoder().decode(dec);
    if (back !== original) throw new Error('base64url roundtrip failed');
  },

  /**
   * Test 4 — version mismatch is rejected.
   */
  async rejectsUnknownVersion(): Promise<void> {
    const payload = { d: 'AAAA', kid: 'app', v: 'crypt2' as const };
    let threw = false;
    try {
      await crypt1Decrypt(payload as unknown as Crypt1Payload, 'x');
    } catch {
      threw = true;
    }
    if (!threw) throw new Error('unknown version must throw');
  },

  /**
   * Test 5 — empty passphrase is rejected.
   */
  async emptyPassphraseRejected(): Promise<void> {
    let threw = false;
    try {
      await crypt1Encrypt('x', '');
    } catch {
      threw = true;
    }
    if (!threw) throw new Error('empty passphrase must throw on encrypt');
  },
};
