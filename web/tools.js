/* Developer Toolbox — pure tool logic, no DOM, no network.
 * Loadable as a plain browser script (window.DevToolbox) or via require() in node. */
(function (root) {
  "use strict";

  const enc = new TextEncoder();
  const decFatal = new TextDecoder("utf-8", { fatal: true });
  const bytesOf = (s) => enc.encode(s);
  const hexOf = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  function fromHex(s) {
    const t = String(s).replace(/[\s:]/g, "");
    if (!/^[0-9a-fA-F]*$/.test(t) || t.length % 2) throw new Error("invalid hex string");
    const out = new Uint8Array(t.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(t.substr(i * 2, 2), 16);
    return out;
  }
  const cryptoObj = root.crypto || (typeof require === "function" ? require("crypto").webcrypto : undefined);
  function randBytes(n) {
    const b = new Uint8Array(n);
    cryptoObj.getRandomValues(b);
    return b;
  }
  function randIndex(max) {
    if (max <= 0 || max > 256) throw new Error("randIndex: max out of range");
    const limit = 256 - (256 % max);
    for (;;) {
      const x = randBytes(1)[0];
      if (x < limit) return x % max;
    }
  }
  const MASK64 = (1n << 64n) - 1n;
  const rotl32 = (x, n) => ((x << n) | (x >>> (32 - n))) | 0;
  const rotr64 = (x, n) => ((x >> n) | (x << (64n - n))) & MASK64;

  /* ---------- hashes ---------- */

  function primes(n) {
    const out = [];
    for (let c = 2; out.length < n; c++) {
      let ok = true;
      for (let d = 2; d * d <= c; d++) if (c % d === 0) { ok = false; break; }
      if (ok) out.push(c);
    }
    return out;
  }
  function isqrtBig(n) {
    if (n < 2n) return n;
    let x = 1n << BigInt(Math.ceil(n.toString(2).length / 2));
    for (;;) {
      const y = (x + n / x) / 2n;
      if (y >= x) return x;
      x = y;
    }
  }
  function icbrtBig(n) {
    if (n < 2n) return n;
    let x = 1n << BigInt(Math.ceil(n.toString(2).length / 3));
    for (;;) {
      const y = (2n * x + n / (x * x)) / 3n;
      if (y >= x) return x;
      x = y;
    }
  }
  const P80 = primes(80);
  const K256 = P80.slice(0, 64).map((p) => Number(icbrtBig(BigInt(p) << 96n) & 0xffffffffn));
  const H256 = P80.slice(0, 8).map((p) => Number(isqrtBig(BigInt(p) << 64n) & 0xffffffffn));
  const K512 = P80.map((p) => icbrtBig(BigInt(p) << 192n) & MASK64);
  const H512 = P80.slice(0, 8).map((p) => isqrtBig(BigInt(p) << 128n) & MASK64);
  const H384 = [
    0xcbbb9d5dc1059ed8n, 0x629a292a367cd507n, 0x9159015a3070dd17n, 0x152fecd8f70e5939n,
    0x67332667ffc00b31n, 0x8eb44a8768581511n, 0xdb0c2e0d64f98fa7n, 0x47b5481dbefa4fa4n,
  ];

  function padBE(msg, lenBytes) {
    const block = lenBytes === 8 ? 64 : 128;
    const bitLen = BigInt(msg.length) * 8n;
    const padLen = (block - ((msg.length + 1 + lenBytes) % block)) % block;
    const out = new Uint8Array(msg.length + 1 + padLen + lenBytes);
    out.set(msg);
    out[msg.length] = 0x80;
    for (let i = 0; i < lenBytes; i++) out[out.length - 1 - i] = Number((bitLen >> BigInt(8 * i)) & 0xffn);
    return out;
  }

  function sha256(msg) {
    const data = padBE(msg, 8);
    const h = H256.slice();
    const w = new Int32Array(64);
    for (let off = 0; off < data.length; off += 64) {
      for (let i = 0; i < 16; i++) w[i] = (data[off + i * 4] << 24) | (data[off + i * 4 + 1] << 16) | (data[off + i * 4 + 2] << 8) | data[off + i * 4 + 3];
      for (let i = 16; i < 64; i++) {
        const s0 = (rotl32(w[i - 15], 25) ^ rotl32(w[i - 15], 14) ^ (w[i - 15] >>> 3)) | 0;
        const s1 = (rotl32(w[i - 2], 15) ^ rotl32(w[i - 2], 13) ^ (w[i - 2] >>> 10)) | 0;
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
      }
      let [a, b, c, d, e, f, g, hh] = h;
      for (let i = 0; i < 64; i++) {
        const S1 = (rotl32(e, 26) ^ rotl32(e, 21) ^ rotl32(e, 7)) | 0;
        const ch = ((e & f) ^ (~e & g)) | 0;
        const t1 = (hh + S1 + ch + K256[i] + w[i]) | 0;
        const S0 = (rotl32(a, 30) ^ rotl32(a, 19) ^ rotl32(a, 10)) | 0;
        const maj = ((a & b) ^ (a & c) ^ (b & c)) | 0;
        const t2 = (S0 + maj) | 0;
        hh = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      h[0] = (h[0] + a) | 0; h[1] = (h[1] + b) | 0; h[2] = (h[2] + c) | 0; h[3] = (h[3] + d) | 0;
      h[4] = (h[4] + e) | 0; h[5] = (h[5] + f) | 0; h[6] = (h[6] + g) | 0; h[7] = (h[7] + hh) | 0;
    }
    const out = new Uint8Array(32);
    h.forEach((x, i) => { out[i * 4] = x >>> 24; out[i * 4 + 1] = x >>> 16; out[i * 4 + 2] = x >>> 8; out[i * 4 + 3] = x; });
    return out;
  }

  function sha512core(msg, init, outLen) {
    const data = padBE(msg, 16);
    const h = init.slice();
    const w = new Array(80);
    for (let off = 0; off < data.length; off += 128) {
      for (let i = 0; i < 16; i++) {
        let v = 0n;
        for (let j = 0; j < 8; j++) v = (v << 8n) | BigInt(data[off + i * 8 + j]);
        w[i] = v;
      }
      for (let i = 16; i < 80; i++) {
        const s0 = rotr64(w[i - 15], 1n) ^ rotr64(w[i - 15], 8n) ^ (w[i - 15] >> 7n);
        const s1 = rotr64(w[i - 2], 19n) ^ rotr64(w[i - 2], 61n) ^ (w[i - 2] >> 6n);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & MASK64;
      }
      let [a, b, c, d, e, f, g, hh] = h;
      for (let i = 0; i < 80; i++) {
        const S1 = rotr64(e, 14n) ^ rotr64(e, 18n) ^ rotr64(e, 41n);
        const ch = (e & f) ^ (~e & MASK64 & g);
        const t1 = (hh + S1 + ch + K512[i] + w[i]) & MASK64;
        const S0 = rotr64(a, 28n) ^ rotr64(a, 34n) ^ rotr64(a, 39n);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + maj) & MASK64;
        hh = g; g = f; f = e; e = (d + t1) & MASK64; d = c; c = b; b = a; a = (t1 + t2) & MASK64;
      }
      h[0] = (h[0] + a) & MASK64; h[1] = (h[1] + b) & MASK64; h[2] = (h[2] + c) & MASK64; h[3] = (h[3] + d) & MASK64;
      h[4] = (h[4] + e) & MASK64; h[5] = (h[5] + f) & MASK64; h[6] = (h[6] + g) & MASK64; h[7] = (h[7] + hh) & MASK64;
    }
    const out = new Uint8Array(outLen);
    for (let i = 0; i < outLen; i++) out[i] = Number((h[i >> 3] >> BigInt(56 - 8 * (i & 7))) & 0xffn);
    return out;
  }
  const sha512 = (m) => sha512core(m, H512, 64);
  const sha384 = (m) => sha512core(m, H384, 48);

  function sha1(msg) {
    const data = padBE(msg, 8);
    let h0 = 0x67452301 | 0, h1 = 0xefcdab89 | 0, h2 = 0x98badcfe | 0, h3 = 0x10325476 | 0, h4 = 0xc3d2e1f0 | 0;
    const w = new Int32Array(80);
    for (let off = 0; off < data.length; off += 64) {
      for (let i = 0; i < 16; i++) w[i] = (data[off + i * 4] << 24) | (data[off + i * 4 + 1] << 16) | (data[off + i * 4 + 2] << 8) | data[off + i * 4 + 3];
      for (let i = 16; i < 80; i++) w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
      let a = h0, b = h1, c = h2, d = h3, e = h4;
      for (let i = 0; i < 80; i++) {
        let f, k;
        if (i < 20) { f = ((b & c) | (~b & d)) | 0; k = 0x5a827999; }
        else if (i < 40) { f = (b ^ c ^ d) | 0; k = 0x6ed9eba1; }
        else if (i < 60) { f = ((b & c) | (b & d) | (c & d)) | 0; k = 0x8f1bbcdc; }
        else { f = (b ^ c ^ d) | 0; k = 0xca62c1d6; }
        const t = (rotl32(a, 5) + f + e + k + w[i]) | 0;
        e = d; d = c; c = rotl32(b, 30); b = a; a = t;
      }
      h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0; h4 = (h4 + e) | 0;
    }
    const out = new Uint8Array(20);
    [h0, h1, h2, h3, h4].forEach((x, i) => { out[i * 4] = x >>> 24; out[i * 4 + 1] = x >>> 16; out[i * 4 + 2] = x >>> 8; out[i * 4 + 3] = x; });
    return out;
  }

  function md5(msg) {
    const S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
      5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
      4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
      6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
    const K = new Int32Array(64);
    for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) | 0;
    const bitLen = msg.length * 8;
    const padLen = (56 - ((msg.length + 1) % 64) + 64) % 64;
    const data = new Uint8Array(msg.length + 1 + padLen + 8);
    data.set(msg);
    data[msg.length] = 0x80;
    for (let i = 0; i < 8; i++) data[data.length - 8 + i] = (bitLen / Math.pow(2, 8 * i)) & 0xff;
    let a0 = 0x67452301 | 0, b0 = 0xefcdab89 | 0, c0 = 0x98badcfe | 0, d0 = 0x10325476 | 0;
    for (let off = 0; off < data.length; off += 64) {
      const M = new Int32Array(16);
      for (let i = 0; i < 16; i++) M[i] = data[off + i * 4] | (data[off + i * 4 + 1] << 8) | (data[off + i * 4 + 2] << 16) | (data[off + i * 4 + 3] << 24);
      let A = a0, B = b0, C = c0, D = d0;
      for (let i = 0; i < 64; i++) {
        let F, g;
        if (i < 16) { F = ((B & C) | (~B & D)) | 0; g = i; }
        else if (i < 32) { F = ((D & B) | (~D & C)) | 0; g = (5 * i + 1) % 16; }
        else if (i < 48) { F = (B ^ C ^ D) | 0; g = (3 * i + 5) % 16; }
        else { F = (C ^ (B | ~D)) | 0; g = (7 * i) % 16; }
        F = (F + A + K[i] + M[g]) | 0;
        A = D; D = C; C = B; B = (B + rotl32(F, S[i])) | 0;
      }
      a0 = (a0 + A) | 0; b0 = (b0 + B) | 0; c0 = (c0 + C) | 0; d0 = (d0 + D) | 0;
    }
    const out = new Uint8Array(16);
    [a0, b0, c0, d0].forEach((x, i) => { out[i * 4] = x; out[i * 4 + 1] = x >>> 8; out[i * 4 + 2] = x >>> 16; out[i * 4 + 3] = x >>> 24; });
    return out;
  }

  const HASHES = {
    md5: { fn: md5, block: 64 },
    "sha-1": { fn: sha1, block: 64 },
    "sha-256": { fn: sha256, block: 64 },
    "sha-384": { fn: sha384, block: 128 },
    "sha-512": { fn: sha512, block: 128 },
  };
  function hmac(alg, key, msg) {
    const h = HASHES[alg];
    if (!h) throw new Error("unsupported hash: " + alg);
    let k = key.length > h.block ? h.fn(key) : key;
    const pad = new Uint8Array(h.block);
    pad.set(k);
    const inner = new Uint8Array(h.block + msg.length);
    const outer = new Uint8Array(h.block + h.fn(new Uint8Array(0)).length);
    for (let i = 0; i < h.block; i++) { inner[i] = pad[i] ^ 0x36; outer[i] = pad[i] ^ 0x5c; }
    inner.set(msg, h.block);
    outer.set(h.fn(inner), h.block);
    return h.fn(outer);
  }
  const hash = {
    digest: (alg, data) => {
      const h = HASHES[alg];
      if (!h) throw new Error("unsupported hash: " + alg);
      return h.fn(data);
    },
    hmac,
    algorithms: Object.keys(HASHES),
  };

  /* ---------- base64 ---------- */

  const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  function b64EncodeBytes(b, urlsafe, padding) {
    let out = "";
    for (let i = 0; i < b.length; i += 3) {
      const n = (b[i] << 16) | ((i + 1 < b.length ? b[i + 1] : 0) << 8) | (i + 2 < b.length ? b[i + 2] : 0);
      out += B64[(n >>> 18) & 63] + B64[(n >>> 12) & 63];
      out += i + 1 < b.length ? B64[(n >>> 6) & 63] : padding ? "=" : "";
      out += i + 2 < b.length ? B64[n & 63] : padding ? "=" : "";
    }
    return urlsafe ? out.replace(/\+/g, "-").replace(/\//g, "_") : out;
  }
  function b64DecodeBytes(s) {
    let t = String(s).replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
    t = t.replace(/=+$/, "");
    if (!/^[A-Za-z0-9+/]*$/.test(t)) throw new Error("invalid Base64 characters");
    if (t.length % 4 === 1) throw new Error("invalid Base64 length");
    const out = [];
    for (let i = 0; i < t.length; i += 4) {
      const chunk = t.slice(i, i + 4);
      let n = 0;
      for (let j = 0; j < 4; j++) n = (n << 6) | (j < chunk.length ? B64.indexOf(chunk[j]) : 0);
      out.push((n >>> 16) & 255);
      if (chunk.length > 2) out.push((n >>> 8) & 255);
      if (chunk.length > 3) out.push(n & 255);
    }
    return new Uint8Array(out);
  }
  const base64 = {
    encode: (text, opts = {}) => b64EncodeBytes(bytesOf(text), !!opts.urlsafe, opts.padding !== false),
    decodeBytes: b64DecodeBytes,
    decode: (s) => {
      const b = b64DecodeBytes(s);
      try {
        return { ok: true, text: decFatal.decode(b), hex: hexOf(b) };
      } catch {
        return { ok: false, text: "", hex: hexOf(b), reason: "decoded bytes are not valid UTF-8" };
      }
    },
    encodeBytes: b64EncodeBytes,
  };

  /* ---------- URL ---------- */

  const url = {
    encode: (text, mode) => {
      if (mode === "uri") return encodeURI(text);
      if (mode === "form") return encodeURIComponent(text).replace(/%20/g, "+");
      return encodeURIComponent(text);
    },
    decode: (text, mode) => {
      const t = mode === "form" ? String(text).replace(/\+/g, " ") : String(text);
      try {
        return { ok: true, text: mode === "uri" ? decodeURI(t) : decodeURIComponent(t) };
      } catch (e) {
        return { ok: false, text: "", reason: "malformed percent-escape: " + e.message };
      }
    },
  };

  /* ---------- Unicode ---------- */

  const unicode = {
    escape: (text, style) => {
      let out = "";
      for (const ch of String(text)) {
        const cp = ch.codePointAt(0);
        if (cp < 128) { out += ch; continue; }
        if (style === "html") out += "&#x" + cp.toString(16).toUpperCase() + ";";
        else if (style === "es6") out += "\\u{" + cp.toString(16).toUpperCase() + "}";
        else if (cp > 0xffff) {
          const v = cp - 0x10000;
          out += "\\u" + (0xd800 + (v >> 10)).toString(16).toUpperCase().padStart(4, "0");
          out += "\\u" + (0xdc00 + (v & 0x3ff)).toString(16).toUpperCase().padStart(4, "0");
        } else out += "\\u" + cp.toString(16).toUpperCase().padStart(4, "0");
      }
      return out;
    },
    unescape: (text) =>
      String(text).replace(/\\u\{([0-9a-fA-F]+)\}|\\u([0-9a-fA-F]{4})|&#x([0-9a-fA-F]+);|&#(\d+);/g, (m, es6, js, htmlHex, htmlDec) => {
        const cp = es6 !== undefined ? parseInt(es6, 16) : js !== undefined ? parseInt(js, 16) : htmlHex !== undefined ? parseInt(htmlHex, 16) : parseInt(htmlDec, 10);
        if (cp > 0x10ffff) throw new Error("codepoint out of range: " + cp);
        return js !== undefined ? String.fromCharCode(cp) : String.fromCodePoint(cp);
      }),
    codepoints: (text) =>
      Array.from(String(text)).map((ch) => {
        const cp = ch.codePointAt(0);
        return {
          ch,
          cp: "U+" + cp.toString(16).toUpperCase().padStart(4, "0"),
          dec: cp,
          utf8: hexOf(bytesOf(ch)),
          utf16: ch.length,
        };
      }),
  };

  /* ---------- timestamp ---------- */

  const pad2 = (n) => String(n).padStart(2, "0");
  function fmtDate(d, utc) {
    const g = utc ? [d.getUTCFullYear(), d.getUTCMonth() + 1, d.getUTCDate(), d.getUTCHours(), d.getUTCMinutes(), d.getUTCSeconds()] : [d.getFullYear(), d.getMonth() + 1, d.getDate(), d.getHours(), d.getMinutes(), d.getSeconds()];
    return `${g[0]}-${pad2(g[1])}-${pad2(g[2])} ${pad2(g[3])}:${pad2(g[4])}:${pad2(g[5])}` + (utc ? " UTC" : "");
  }
  const ts = {
    unitOf: (n) => {
      const a = n < 0n ? -n : n;
      if (a < 100000000000n) return "s";
      if (a < 100000000000000n) return "ms";
      if (a < 100000000000000000n) return "us";
      return "ns";
    },
    parse: (input) => {
      const t = String(input).trim();
      if (!t) throw new Error("empty input");
      if (/^-?\d+$/.test(t)) {
        const n = BigInt(t);
        const unit = ts.unitOf(n);
        const ms = unit === "s" ? n * 1000n : unit === "ms" ? n : unit === "us" ? n / 1000n : n / 1000000n;
        return { ms: Number(ms), unit };
      }
      if (/^-?\d+\.\d+$/.test(t)) return { ms: Math.round(parseFloat(t) * 1000), unit: "s (fractional)" };
      const p = Date.parse(t);
      if (Number.isNaN(p)) throw new Error("not a timestamp or parseable date: " + t);
      return { ms: p, unit: "date string" };
    },
    formats: (ms) => {
      const d = new Date(ms);
      if (Number.isNaN(d.getTime())) throw new Error("timestamp out of range");
      return {
        local: fmtDate(d, false),
        utc: fmtDate(d, true),
        iso: d.toISOString(),
        seconds: Math.floor(ms / 1000),
        milliseconds: ms,
      };
    },
    fromDate: (text, utc) => {
      const t = String(text).trim().replace(" ", "T");
      const p = Date.parse(utc && !/[Zz]|[+-]\d\d:?\d\d$/.test(t) ? t + "Z" : t);
      if (Number.isNaN(p)) throw new Error("not a parseable date: " + text);
      return p;
    },
    fmt: fmtDate,
  };

  /* ---------- password ---------- */

  const CHARSETS = {
    lower: "abcdefghijklmnopqrstuvwxyz",
    upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    digits: "0123456789",
    symbols: "!@#$%^&*()-_=+[]{};:,.<>?/~",
  };
  const AMBIGUOUS = "Il1O0o";
  const password = {
    charsets: CHARSETS,
    generate: (opts = {}) => {
      const length = Math.max(4, Math.min(256, opts.length | 0 || 16));
      const classes = ["lower", "upper", "digits", "symbols"].filter((k) => opts[k] !== false && (opts[k] || k === "lower" || k === "upper" || k === "digits"));
      const active = classes.length ? classes : ["lower"];
      let pools = active.map((k) => CHARSETS[k]);
      if (opts.excludeAmbiguous) pools = pools.map((p) => Array.from(p).filter((c) => !AMBIGUOUS.includes(c)).join(""));
      pools = pools.filter((p) => p.length);
      if (!pools.length) throw new Error("no characters left in the selected sets");
      const pool = pools.join("");
      const chars = [];
      for (const p of pools) chars.push(p[randIndex(p.length)]);
      while (chars.length < length) chars.push(pool[randIndex(pool.length)]);
      for (let i = chars.length - 1; i > 0; i--) {
        const j = randIndex(i + 1);
        [chars[i], chars[j]] = [chars[j], chars[i]];
      }
      return { text: chars.slice(0, length).join(""), entropyBits: Math.round(length * Math.log2(pool.length)) };
    },
  };

  /* ---------- JSON ---------- */

  function locateJsonError(s) {
    let i = 0;
    const n = s.length;
    const ws = () => { while (i < n && /\s/.test(s[i])) i++; };
    const fail = () => { throw i; };
    function string() {
      i++;
      while (i < n) {
        const c = s[i];
        if (c === '"') { i++; return; }
        if (c === "\\") {
          i++;
          const e = s[i];
          if (e === undefined) fail();
          if ('"\\/bfnrt'.includes(e)) { i++; continue; }
          if (e === "u") { i++; for (let k = 0; k < 4; k++) { if (!/[0-9a-fA-F]/.test(s[i] || "")) fail(); i++; } continue; }
          fail();
        }
        if (c.charCodeAt(0) < 0x20) fail();
        i++;
      }
      fail();
    }
    function number() {
      if (s[i] === "-") i++;
      if (s[i] === "0") i++;
      else if (s[i] >= "1" && s[i] <= "9") { while (i < n && s[i] >= "0" && s[i] <= "9") i++; }
      else fail();
      if (s[i] === ".") { i++; if (!(s[i] >= "0" && s[i] <= "9")) fail(); while (i < n && s[i] >= "0" && s[i] <= "9") i++; }
      if (s[i] === "e" || s[i] === "E") { i++; if (s[i] === "+" || s[i] === "-") i++; if (!(s[i] >= "0" && s[i] <= "9")) fail(); while (i < n && s[i] >= "0" && s[i] <= "9") i++; }
    }
    function value() {
      ws();
      if (i >= n) fail();
      const c = s[i];
      if (c === "{") {
        i++; ws();
        if (s[i] === "}") { i++; return; }
        for (;;) {
          ws();
          if (s[i] !== '"') fail();
          string(); ws();
          if (s[i] !== ":") fail();
          i++;
          value(); ws();
          if (s[i] === ",") { i++; continue; }
          if (s[i] === "}") { i++; return; }
          fail();
        }
      }
      if (c === "[") {
        i++; ws();
        if (s[i] === "]") { i++; return; }
        for (;;) {
          value(); ws();
          if (s[i] === ",") { i++; continue; }
          if (s[i] === "]") { i++; return; }
          fail();
        }
      }
      if (c === '"') { string(); return; }
      if (c === "-" || (c >= "0" && c <= "9")) { number(); return; }
      if (s.startsWith("true", i)) { i += 4; return; }
      if (s.startsWith("false", i)) { i += 5; return; }
      if (s.startsWith("null", i)) { i += 4; return; }
      fail();
    }
    try {
      value(); ws();
      if (i < n) fail();
      return -1;
    } catch (pos) {
      return typeof pos === "number" ? pos : -1;
    }
  }
  function parseWithPos(text) {
    try {
      return { ok: true, value: JSON.parse(text) };
    } catch (e) {
      const msg = String(e.message);
      let line, column;
      const lc = /line (\d+) column (\d+)/.exec(msg);
      const pos = /position (\d+)/.exec(msg);
      let p = pos ? +pos[1] : -1;
      if (lc) { line = +lc[1]; column = +lc[2]; }
      else {
        if (p < 0) p = locateJsonError(String(text));
        if (p >= 0) {
          const before = String(text).slice(0, p);
          line = before.split("\n").length;
          column = p - before.lastIndexOf("\n");
        }
      }
      return { ok: false, message: msg, line, column };
    }
  }
  const sortedReplacer = (k, v) => {
    if (v && typeof v === "object" && !Array.isArray(v)) {
      const out = {};
      for (const key of Object.keys(v).sort()) out[key] = v[key];
      return out;
    }
    return v;
  };
  const json = {
    parse: parseWithPos,
    format: (text, opts = {}) => {
      const p = parseWithPos(text);
      if (!p.ok) return p;
      const indent = opts.tab ? "\t" : opts.indent === undefined ? 2 : Math.max(0, Math.min(8, opts.indent | 0));
      return { ok: true, text: JSON.stringify(p.value, opts.sortKeys ? sortedReplacer : null, indent) };
    },
    minify: (text) => {
      const p = parseWithPos(text);
      if (!p.ok) return p;
      return { ok: true, text: JSON.stringify(p.value) };
    },
  };

  /* ---------- IDs ---------- */

  const uuidFmt = (b) => hexOf(b.slice(0, 4)) + "-" + hexOf(b.slice(4, 6)) + "-" + hexOf(b.slice(6, 8)) + "-" + hexOf(b.slice(8, 10)) + "-" + hexOf(b.slice(10, 16));
  let sfLastMs = -1, sfSeq = 0, oidCounter = randBytes(3), oidMachine = randBytes(5);
  const ids = {
    uuidv4: () => {
      const b = randBytes(16);
      b[6] = (b[6] & 0x0f) | 0x40;
      b[8] = (b[8] & 0x3f) | 0x80;
      return uuidFmt(b);
    },
    uuidv7: () => {
      const b = randBytes(16);
      const ms = Date.now();
      for (let i = 0; i < 6; i++) b[i] = Number((BigInt(ms) >> BigInt(8 * (5 - i))) & 0xffn);
      b[6] = (b[6] & 0x0f) | 0x70;
      b[8] = (b[8] & 0x3f) | 0x80;
      return uuidFmt(b);
    },
    nanoid: (size = 21) => {
      const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
      const n = Math.max(1, Math.min(256, size | 0));
      let out = "";
      const b = randBytes(n);
      for (let i = 0; i < n; i++) out += A[b[i] & 63];
      return out;
    },
    snowflake: (opts = {}) => {
      const epoch = BigInt(opts.epoch ?? 1288834974657);
      const machine = BigInt(opts.machine ?? 0) & 1023n;
      let ms = Date.now();
      if (ms === sfLastMs) {
        sfSeq = (sfSeq + 1) & 4095;
        if (sfSeq === 0) while ((ms = Date.now()) === sfLastMs) { /* next millisecond */ }
      } else sfSeq = 0;
      sfLastMs = ms;
      return ((BigInt(ms) - epoch) << 22n | machine << 12n | BigInt(sfSeq)).toString();
    },
    snowflakeDecode: (id, epoch = 1288834974657) => {
      const v = BigInt(id);
      return {
        time: new Date(Number((v >> 22n) + BigInt(epoch))).toISOString(),
        machine: Number((v >> 12n) & 1023n),
        sequence: Number(v & 4095n),
      };
    },
    objectid: () => {
      const tsSec = Math.floor(Date.now() / 1000);
      const b = new Uint8Array(12);
      for (let i = 0; i < 4; i++) b[i] = (tsSec >>> (8 * (3 - i))) & 255;
      b.set(oidMachine, 4);
      for (let i = 2; i >= 0; i--) {
        oidCounter[i] = (oidCounter[i] + 1) & 255;
        if (oidCounter[i]) break;
      }
      b.set(oidCounter, 9);
      return hexOf(b);
    },
  };

  /* ---------- JWT ---------- */

  const b64url = (b) => b64EncodeBytes(b, true, false);
  const unb64url = (s) => b64DecodeBytes(s);
  const JWT_ALGS = { HS256: "sha-256", HS384: "sha-384", HS512: "sha-512" };
  function claimTimes(payload) {
    const out = [];
    const now = Date.now() / 1000;
    for (const k of ["iat", "nbf", "exp"]) {
      if (typeof payload[k] === "number") {
        const when = new Date(payload[k] * 1000);
        let status = "";
        if (k === "exp") status = payload[k] < now ? "expired" : "valid";
        if (k === "nbf") status = payload[k] > now ? "not yet valid" : "valid";
        out.push({ claim: k, value: payload[k], iso: when.toISOString(), status });
      }
    }
    return out;
  }
  const jwt = {
    algorithms: Object.keys(JWT_ALGS),
    parse: (token) => {
      const parts = String(token).trim().split(".");
      if (parts.length !== 3) throw new Error("a JWT has three dot-separated parts (header.payload.signature)");
      let header, payload;
      try { header = JSON.parse(decFatal.decode(unb64url(parts[0]))); } catch (e) { throw new Error("header is not valid Base64URL JSON: " + e.message); }
      try { payload = JSON.parse(decFatal.decode(unb64url(parts[1]))); } catch (e) { throw new Error("payload is not valid Base64URL JSON: " + e.message); }
      return { header, payload, signature: parts[2], alg: header.alg || "(none)", times: claimTimes(payload) };
    },
    sign: (payloadText, secret, alg = "HS256") => {
      const h = JWT_ALGS[alg];
      if (!h) throw new Error("unsupported algorithm: " + alg + " (only HS256/HS384/HS512 sign locally)");
      const p = parseWithPos(payloadText);
      if (!p.ok) throw new Error("payload must be JSON: " + p.message);
      const headerJson = JSON.stringify({ alg, typ: "JWT" });
      const payloadJson = JSON.stringify(p.value);
      const input = b64url(bytesOf(headerJson)) + "." + b64url(bytesOf(payloadJson));
      return input + "." + b64url(hmac(h, bytesOf(secret), bytesOf(input)));
    },
    verify: (token, secret) => {
      const parts = String(token).trim().split(".");
      if (parts.length !== 3) return { ok: false, reason: "not three parts" };
      let header;
      try { header = JSON.parse(decFatal.decode(unb64url(parts[0]))); } catch { return { ok: false, reason: "bad header" }; }
      const h = JWT_ALGS[header.alg];
      if (!h) return { ok: false, reason: "algorithm " + header.alg + " cannot be verified locally (HS256/384/512 only)" };
      const expect = hmac(h, bytesOf(secret), bytesOf(parts[0] + "." + parts[1]));
      let got;
      try { got = unb64url(parts[2]); } catch { return { ok: false, reason: "bad signature encoding" }; }
      if (got.length !== expect.length) return { ok: false, reason: "signature mismatch" };
      let diff = 0;
      for (let i = 0; i < expect.length; i++) diff |= expect[i] ^ got[i];
      return diff === 0 ? { ok: true } : { ok: false, reason: "signature mismatch" };
    },
  };

  /* ---------- Cron ---------- */

  const MONTH_NAMES = { JAN: 1, FEB: 2, MAR: 3, APR: 4, MAY: 5, JUN: 6, JUL: 7, AUG: 8, SEP: 9, OCT: 10, NOV: 11, DEC: 12 };
  const DOW_NAMES = { SUN: 0, MON: 1, TUE: 2, WED: 3, THU: 4, FRI: 5, SAT: 6 };
  function fieldNum(tok, names, min, max) {
    const up = tok.toUpperCase();
    if (names && up in names) return names[up];
    if (!/^\d+$/.test(tok)) throw new Error("bad cron value: " + tok);
    let v = +tok;
    if (names === DOW_NAMES && v === 7) v = 0;
    if (v < min || v > max) throw new Error(`cron value ${tok} out of range ${min}-${max}`);
    return v;
  }
  function parseField(spec, min, max, names) {
    const set = new Set();
    for (const part of String(spec).split(",")) {
      if (!part) throw new Error("empty cron list item");
      const [range, stepStr] = part.split("/");
      const step = stepStr === undefined ? 1 : +stepStr;
      if (!Number.isInteger(step) || step < 1) throw new Error("bad cron step: " + part);
      let lo, hi;
      if (range === "*" || range === "?") { lo = min; hi = max; }
      else if (range.includes("-")) {
        const [a, b] = range.split("-");
        lo = fieldNum(a, names, min, max);
        hi = fieldNum(b, names, min, max);
        if (lo > hi) throw new Error("reversed cron range: " + range);
      } else {
        lo = fieldNum(range, names, min, max);
        hi = stepStr === undefined ? lo : max;
      }
      for (let v = lo; v <= hi; v += step) set.add(v);
    }
    return set;
  }
  function cronParse(expr) {
    const toks = String(expr).trim().split(/\s+/);
    let sec, rest;
    if (toks.length === 5) { sec = new Set([0]); rest = toks; }
    else if (toks.length === 6) { sec = parseField(toks[0], 0, 59); rest = toks.slice(1); }
    else throw new Error("cron needs 5 fields (min hour dom month dow) or 6 (with seconds)");
    const [mi, h, dom, mo, dow] = rest;
    return {
      sec,
      min: parseField(mi, 0, 59),
      hour: parseField(h, 0, 23),
      dom: parseField(dom, 1, 31),
      month: parseField(mo, 1, 12, MONTH_NAMES),
      dow: parseField(dow, 0, 6, DOW_NAMES),
      domR: dom !== "*" && dom !== "?",
      dowR: dow !== "*" && dow !== "?",
      six: toks.length === 6,
      specs: { sec: toks.length === 6 ? toks[0] : "0", min: mi, hour: h, dom, month: mo, dow },
    };
  }
  function cronNext(expr, fromMs, count) {
    const c = cronParse(expr);
    const out = [];
    const d = new Date(fromMs);
    d.setMilliseconds(0);
    if (c.six) d.setSeconds(d.getSeconds() + 1);
    else { d.setSeconds(0, 0); d.setMinutes(d.getMinutes() + 1); }
    const deadline = fromMs + 4 * 366 * 24 * 3600 * 1000;
    let steps = 0;
    while (out.length < count && d.getTime() < deadline && steps++ < 500000) {
      if (!c.month.has(d.getMonth() + 1)) { d.setDate(1); d.setHours(0, 0, 0, 0); d.setMonth(d.getMonth() + 1); continue; }
      const domOk = c.dom.has(d.getDate()), dowOk = c.dow.has(d.getDay());
      const dayOk = c.domR && c.dowR ? domOk || dowOk : domOk && dowOk;
      if (!dayOk) { d.setHours(0, 0, 0, 0); d.setDate(d.getDate() + 1); continue; }
      if (!c.hour.has(d.getHours())) { d.setMinutes(0, 0, 0); d.setHours(d.getHours() + 1); continue; }
      if (!c.min.has(d.getMinutes())) { d.setSeconds(0, 0); d.setMinutes(d.getMinutes() + 1); continue; }
      if (!c.sec.has(d.getSeconds())) { d.setSeconds(d.getSeconds() + 1); continue; }
      out.push(new Date(d.getTime()));
      if (c.six) d.setSeconds(d.getSeconds() + 1);
      else d.setMinutes(d.getMinutes() + 1);
    }
    return { runs: out, truncated: out.length < count };
  }
  function listDesc(set, spec, every, unit) {
    if (spec === "*" || spec === "?") return every + " " + unit;
    const m = /^\*\/(\d+)$/.exec(spec);
    if (m) return `every ${m[1]} ${unit}s`;
    return unit + " " + Array.from(set).sort((a, b) => a - b).join(", ");
  }
  function cronDescribe(expr, lang) {
    const c = cronParse(expr);
    const s = c.specs;
    const zh = lang === "zh";
    const simple = !c.six && s.min !== "*" && s.hour !== "*" && s.dom !== "*" && s.month === "*" && s.dow === "*" ? "monthly"
      : !c.six && s.min !== "*" && s.hour !== "*" && s.dom === "*" && s.month === "*" && s.dow !== "*" ? "weekly"
      : !c.six && s.min !== "*" && s.hour !== "*" && s.dom === "*" && s.month === "*" && s.dow === "*" ? "daily"
      : null;
    if (!c.six && s.min === "*" && s.hour === "*" && s.dom === "*" && s.month === "*" && s.dow === "*") return zh ? "每分钟" : "Every minute";
    const stepMin = /^\*\/(\d+)$/.exec(s.min);
    if (!c.six && stepMin && s.hour === "*" && s.dom === "*" && s.month === "*" && s.dow === "*") return zh ? `每 ${stepMin[1]} 分钟` : `Every ${stepMin[1]} minutes`;
    const at = (h, m) => `${pad2(h)}:${pad2(m)}`;
    if (simple === "daily") return zh ? `每天 ${at(s.hour, s.min)}` : `Daily at ${at(s.hour, s.min)}`;
    if (simple === "weekly") {
      const days = Array.from(c.dow).sort((a, b) => a - b).map((d) => (zh ? ["周日", "周一", "周二", "周三", "周四", "周五", "周六"][d] : ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"][d]));
      return zh ? `每${days.join("、")} ${at(s.hour, s.min)}` : `Weekly on ${days.join(", ")} at ${at(s.hour, s.min)}`;
    }
    if (simple === "monthly") return zh ? `每月 ${s.dom} 日 ${at(s.hour, s.min)}` : `Monthly on day ${s.dom} at ${at(s.hour, s.min)}`;
    const parts = [];
    if (c.six) parts.push(zh ? "秒：" + Array.from(c.sec).sort((a, b) => a - b).join(",") : listDesc(c.sec, s.sec, "every", "second"));
    parts.push(zh ? "分钟：" + (s.min === "*" ? "每" : Array.from(c.min).sort((a, b) => a - b).join(",")) : listDesc(c.min, s.min, "every", "minute"));
    parts.push(zh ? "小时：" + (s.hour === "*" ? "每" : Array.from(c.hour).sort((a, b) => a - b).join(",")) : listDesc(c.hour, s.hour, "every", "hour"));
    parts.push(zh ? "日：" + (s.dom === "*" ? "每" : Array.from(c.dom).sort((a, b) => a - b).join(",")) : listDesc(c.dom, s.dom, "every", "day-of-month"));
    parts.push(zh ? "月：" + (s.month === "*" ? "每" : Array.from(c.month).sort((a, b) => a - b).join(",")) : listDesc(c.month, s.month, "every", "month"));
    parts.push(zh ? "星期：" + (s.dow === "*" ? "每" : Array.from(c.dow).sort((a, b) => a - b).join(",")) : listDesc(c.dow, s.dow, "every", "weekday"));
    return parts.join(zh ? "；" : "; ");
  }
  const cron = { parse: cronParse, next: cronNext, describe: cronDescribe };

  /* ---------- export ---------- */

  const Toolbox = { util: { hexOf, fromHex, bytesOf }, hash, base64, url, unicode, ts, password, json, ids, jwt, cron };
  if (typeof module !== "undefined" && module.exports) module.exports = Toolbox;
  else root.DevToolbox = Toolbox;
})(typeof globalThis !== "undefined" ? globalThis : this);