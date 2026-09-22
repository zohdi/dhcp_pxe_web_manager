/*
 * Minimal browser-side RSA-OAEP/SHA-256 encryptor for the DHCP Manager login.
 *
 * Purpose: keep the plaintext AD password out of the submitted HTTP form payload.
 * This is defense-in-depth only and DOES NOT replace HTTPS/TLS. Because this
 * script and the public key are delivered over HTTP, an active network attacker
 * could replace them and capture credentials before encryption.
 *
 * Requirements: modern browser with BigInt, TextEncoder, atob/btoa, and
 * crypto.getRandomValues(). crypto.getRandomValues() is intentionally used for
 * OAEP randomness; there is no insecure pseudo-random fallback.
 */
(function (global) {
  "use strict";

  const SHA256_K = new Uint32Array([
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  ]);

  function rotr(x, n) {
    return (x >>> n) | (x << (32 - n));
  }

  function sha256(message) {
    const bytes = message instanceof Uint8Array ? message : new Uint8Array(message);
    const bitLength = bytes.length * 8;
    const paddedLength = Math.ceil((bytes.length + 9) / 64) * 64;
    const padded = new Uint8Array(paddedLength);
    padded.set(bytes);
    padded[bytes.length] = 0x80;

    const view = new DataView(padded.buffer);
    const high = Math.floor(bitLength / 0x100000000);
    const low = bitLength >>> 0;
    view.setUint32(paddedLength - 8, high, false);
    view.setUint32(paddedLength - 4, low, false);

    let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
    let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
    const w = new Uint32Array(64);

    for (let offset = 0; offset < paddedLength; offset += 64) {
      for (let i = 0; i < 16; i++) {
        w[i] = view.getUint32(offset + i * 4, false);
      }
      for (let i = 16; i < 64; i++) {
        const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }

      let a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
      for (let i = 0; i < 64; i++) {
        const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const ch = (e & f) ^ (~e & g);
        const temp1 = (h + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
        const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = (S0 + maj) >>> 0;
        h=g; g=f; f=e; e=(d + temp1) >>> 0; d=c; c=b; b=a; a=(temp1 + temp2) >>> 0;
      }

      h0=(h0+a)>>>0; h1=(h1+b)>>>0; h2=(h2+c)>>>0; h3=(h3+d)>>>0;
      h4=(h4+e)>>>0; h5=(h5+f)>>>0; h6=(h6+g)>>>0; h7=(h7+h)>>>0;
    }

    const out = new Uint8Array(32);
    const outView = new DataView(out.buffer);
    [h0,h1,h2,h3,h4,h5,h6,h7].forEach((v, i) => outView.setUint32(i * 4, v, false));
    return out;
  }

  function concat(...arrays) {
    const total = arrays.reduce((sum, a) => sum + a.length, 0);
    const out = new Uint8Array(total);
    let pos = 0;
    for (const a of arrays) {
      out.set(a, pos);
      pos += a.length;
    }
    return out;
  }

  function xor(a, b) {
    if (a.length !== b.length) throw new Error("RSA-OAEP internal length mismatch");
    const out = new Uint8Array(a.length);
    for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
    return out;
  }

  function mgf1(seed, maskLength) {
    const hLen = 32;
    const out = new Uint8Array(maskLength);
    let pos = 0;
    for (let counter = 0; pos < maskLength; counter++) {
      const c = new Uint8Array(4);
      c[0] = (counter >>> 24) & 0xff;
      c[1] = (counter >>> 16) & 0xff;
      c[2] = (counter >>> 8) & 0xff;
      c[3] = counter & 0xff;
      const digest = sha256(concat(seed, c));
      const take = Math.min(hLen, maskLength - pos);
      out.set(digest.subarray(0, take), pos);
      pos += take;
    }
    return out;
  }

  function oaepEncode(message, k) {
    const hLen = 32;
    if (message.length > k - 2 * hLen - 2) {
      throw new Error("AD login payload is too large for RSA-OAEP");
    }
    if (!global.crypto || typeof global.crypto.getRandomValues !== "function") {
      throw new Error("Secure random generator is unavailable in this browser");
    }

    const lHash = sha256(new Uint8Array(0));
    const ps = new Uint8Array(k - message.length - 2 * hLen - 2);
    const db = concat(lHash, ps, new Uint8Array([1]), message);
    const seed = new Uint8Array(hLen);
    global.crypto.getRandomValues(seed);
    const dbMask = mgf1(seed, k - hLen - 1);
    const maskedDB = xor(db, dbMask);
    const seedMask = mgf1(maskedDB, hLen);
    const maskedSeed = xor(seed, seedMask);
    return concat(new Uint8Array([0]), maskedSeed, maskedDB);
  }

  function readLength(bytes, offset) {
    let first = bytes[offset++];
    if ((first & 0x80) === 0) return { length: first, offset };
    const count = first & 0x7f;
    if (count === 0 || count > 4) throw new Error("Unsupported DER length");
    let length = 0;
    for (let i = 0; i < count; i++) length = (length * 256) + bytes[offset++];
    return { length, offset };
  }

  function readTlv(bytes, offset) {
    if (offset >= bytes.length) throw new Error("Invalid DER public key");
    const tag = bytes[offset++];
    const lenInfo = readLength(bytes, offset);
    const valueStart = lenInfo.offset;
    const end = valueStart + lenInfo.length;
    if (end > bytes.length) throw new Error("Invalid DER public key length");
    return { tag, valueStart, end, next: end };
  }

  function pemToBytes(pem) {
    const base64 = pem
      .replace(/-----BEGIN PUBLIC KEY-----/g, "")
      .replace(/-----END PUBLIC KEY-----/g, "")
      .replace(/\s/g, "");
    const binary = global.atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  function integerBytes(bytes, tlv) {
    if (tlv.tag !== 0x02) throw new Error("Invalid RSA public key integer");
    let start = tlv.valueStart;
    while (start < tlv.end - 1 && bytes[start] === 0) start++;
    return bytes.slice(start, tlv.end);
  }

  function parseRsaPublicKey(pem) {
    const der = pemToBytes(pem);
    const spki = readTlv(der, 0);
    if (spki.tag !== 0x30) throw new Error("Invalid SPKI public key");

    let pos = spki.valueStart;
    const algorithm = readTlv(der, pos);
    if (algorithm.tag !== 0x30) throw new Error("Invalid SPKI algorithm");
    pos = algorithm.next;

    const bitString = readTlv(der, pos);
    if (bitString.tag !== 0x03 || der[bitString.valueStart] !== 0) {
      throw new Error("Invalid SPKI RSA bit string");
    }

    const rsaOffset = bitString.valueStart + 1;
    const rsaSeq = readTlv(der, rsaOffset);
    if (rsaSeq.tag !== 0x30) throw new Error("Invalid RSA public key");
    let rsaPos = rsaSeq.valueStart;
    const modulusTlv = readTlv(der, rsaPos);
    rsaPos = modulusTlv.next;
    const exponentTlv = readTlv(der, rsaPos);

    const modulusBytes = integerBytes(der, modulusTlv);
    const exponentBytes = integerBytes(der, exponentTlv);
    return {
      modulusBytes,
      n: bytesToBigInt(modulusBytes),
      e: bytesToBigInt(exponentBytes),
    };
  }

  function bytesToBigInt(bytes) {
    let value = 0n;
    for (const byte of bytes) value = (value << 8n) | BigInt(byte);
    return value;
  }

  function bigIntToBytes(value, length) {
    const out = new Uint8Array(length);
    for (let i = length - 1; i >= 0; i--) {
      out[i] = Number(value & 0xffn);
      value >>= 8n;
    }
    if (value !== 0n) throw new Error("RSA result does not fit modulus length");
    return out;
  }

  function modPow(base, exponent, modulus) {
    if (modulus <= 0n) throw new Error("Invalid RSA modulus");
    let result = 1n;
    base %= modulus;
    while (exponent > 0n) {
      if (exponent & 1n) result = (result * base) % modulus;
      exponent >>= 1n;
      base = (base * base) % modulus;
    }
    return result;
  }

  function toBase64(bytes) {
    let binary = "";
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return global.btoa(binary);
  }

  function encrypt(publicKeyPem, plaintextText) {
    const key = parseRsaPublicKey(publicKeyPem);
    const k = key.modulusBytes.length;
    const message = new TextEncoder().encode(plaintextText);
    const encoded = oaepEncode(message, k);
    const m = bytesToBigInt(encoded);
    if (m >= key.n) throw new Error("RSA-OAEP encoded message exceeds modulus");
    const encrypted = modPow(m, key.e, key.n);
    return toBase64(bigIntToBytes(encrypted, k));
  }

  global.HttpRsaOaep = Object.freeze({ encrypt });
})(typeof window !== "undefined" ? window : globalThis);
