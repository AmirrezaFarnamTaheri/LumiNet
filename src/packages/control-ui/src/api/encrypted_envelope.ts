export interface EncryptedPayloadEnvelope {
  version: number;
  algorithm: string;
  encoding: string;
  iv: string;
  ciphertext: string;
}

export function validateEnvelopeStructure(raw: unknown): EncryptedPayloadEnvelope {
  if (typeof raw !== "object" || raw === null) {
    throw new Error("Invalid envelope: expected JSON object");
  }
  const obj = raw as Record<string, unknown>;
  if (obj.version !== 1) {
    throw new Error(`Unsupported envelope version: expected 1, got ${obj.version}`);
  }
  if (obj.algorithm !== "AES-GCM") {
    throw new Error(`Unsupported envelope algorithm: expected AES-GCM, got ${obj.algorithm}`);
  }
  if (obj.encoding !== "base64url") {
    throw new Error(`Unsupported envelope encoding: expected base64url, got ${obj.encoding}`);
  }
  if (typeof obj.iv !== "string" || obj.iv.length === 0) {
    throw new Error("Envelope missing required iv string");
  }
  if (typeof obj.ciphertext !== "string" || obj.ciphertext.length === 0) {
    throw new Error("Envelope missing required ciphertext string");
  }

  return {
    version: obj.version,
    algorithm: obj.algorithm,
    encoding: obj.encoding,
    iv: obj.iv,
    ciphertext: obj.ciphertext,
  };
}

export function parsePlaintextIps(text: string): string[] {
  const seen = new Set<string>();
  const result: string[] = [];

  const tokens = text.trim().split(/\s+/);
  for (const token of tokens) {
    const trimmed = token.trim();
    if (isValidIpv4(trimmed) && !seen.has(trimmed)) {
      seen.add(trimmed);
      result.push(trimmed);
    }
  }
  return result;
}

function isValidIpv4(value: string): boolean {
  const octets = value.split(".");
  if (octets.length !== 4) return false;
  return octets.every((octet) => {
    const n = Number(octet);
    return !Number.isNaN(n) && n >= 0 && n <= 255 && octet === String(n);
  });
}
