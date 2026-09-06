export class OverTlsCodec {
  constructor(public maxPadding: number = 32) {}

  encodeFrame(payload: Uint8Array, paddingLen: number): Uint8Array {
    const pLen = Math.min(paddingLen, this.maxPadding);
    const nLen = payload.length;
    const total = 6 + nLen + pLen;
    const buf = new Uint8Array(total);

    // Magic 0x544F ('OT')
    buf[0] = 0x54;
    buf[1] = 0x4F;
    buf[2] = 0x01; // Data frame
    buf[3] = pLen;
    buf[4] = (nLen >> 8) & 0xFF;
    buf[5] = nLen & 0xFF;

    buf.set(payload, 6);
    for (let i = 0; i < pLen; i++) {
      buf[6 + nLen + i] = ((i * 37) ^ 0xA5) & 0xFF;
    }
    return buf;
  }

  decodeFrame(buf: Uint8Array): Uint8Array | null {
    if (buf.length < 6) return null;
    if (buf[0] !== 0x54 || buf[1] !== 0x4F) return null;

    const pLen = buf[3];
    const nLen = (buf[4] << 8) | buf[5];
    if (buf.length < 6 + nLen + pLen) return null;

    return buf.slice(6, 6 + nLen);
  }
}
