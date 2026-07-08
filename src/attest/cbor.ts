// Strict minimal CBOR decoder for the App Attest attestation envelope. Parsing only, no
// crypto. The envelope is a small definite length map ({ fmt, attStmt: { x5c, receipt },
// authData }), so only the major types it can contain are implemented: unsigned integers,
// byte strings, text strings, arrays, and maps with text keys. Everything else (indefinite
// lengths, tags, negative integers, floats, simple values) is rejected outright; a decoder
// at a trust boundary should not be generous.

export type CborValue = number | Uint8Array | string | CborValue[] | CborMap;
export interface CborMap {
  [key: string]: CborValue;
}

const MAX_DEPTH = 5;
const MAX_ITEMS = 64; // per array or map; the attestation envelope needs single digits

class Reader {
  private offset = 0;
  constructor(private readonly bytes: Uint8Array) {}

  private need(n: number): void {
    if (this.offset + n > this.bytes.length) throw new Error('cbor: truncated');
  }

  private u8(): number {
    this.need(1);
    const b = this.bytes[this.offset]!;
    this.offset += 1;
    return b;
  }

  private uint(additional: number): number {
    if (additional < 24) return additional;
    if (additional === 24) return this.u8();
    if (additional === 25) {
      this.need(2);
      const v = (this.bytes[this.offset]! << 8) | this.bytes[this.offset + 1]!;
      this.offset += 2;
      return v;
    }
    if (additional === 26) {
      this.need(4);
      let v = 0;
      for (let i = 0; i < 4; i += 1) v = v * 256 + this.bytes[this.offset + i]!;
      this.offset += 4;
      return v;
    }
    // 27 would be a 64 bit length: nothing in an attestation is that large.
    throw new Error('cbor: unsupported length encoding');
  }

  private raw(len: number): Uint8Array {
    this.need(len);
    const out = this.bytes.subarray(this.offset, this.offset + len);
    this.offset += len;
    return out;
  }

  decodeItem(depth: number): CborValue {
    if (depth > MAX_DEPTH) throw new Error('cbor: too deep');
    const head = this.u8();
    const major = head >> 5;
    const additional = head & 0x1f;
    if (additional === 31) throw new Error('cbor: indefinite length rejected');
    switch (major) {
      case 0: // unsigned integer
        return this.uint(additional);
      case 2: // byte string
        return this.raw(this.uint(additional));
      case 3: // text string
        return new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(this.raw(this.uint(additional)));
      case 4: {
        const len = this.uint(additional);
        if (len > MAX_ITEMS) throw new Error('cbor: array too large');
        const arr: CborValue[] = [];
        for (let i = 0; i < len; i += 1) arr.push(this.decodeItem(depth + 1));
        return arr;
      }
      case 5: {
        const len = this.uint(additional);
        if (len > MAX_ITEMS) throw new Error('cbor: map too large');
        const map: CborMap = {};
        for (let i = 0; i < len; i += 1) {
          const key = this.decodeItem(depth + 1);
          if (typeof key !== 'string') throw new Error('cbor: non text map key');
          map[key] = this.decodeItem(depth + 1);
        }
        return map;
      }
      default:
        throw new Error('cbor: unsupported major type');
    }
  }

  done(): boolean {
    return this.offset === this.bytes.length;
  }
}

// Decodes exactly one CBOR item covering the whole buffer. Throws on anything else.
export function decodeCbor(bytes: Uint8Array): CborValue {
  const reader = new Reader(bytes);
  const value = reader.decodeItem(0);
  if (!reader.done()) throw new Error('cbor: trailing bytes');
  return value;
}
