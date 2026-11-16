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

  /* ---------- regex: backtracking VM with a step budget ----------
     The view's CSP blocks Workers and a native RegExp can backtrack
     catastrophically on the IDE's main thread, so matching runs on an
     explicit-stack VM that aborts after a fixed number of steps. */

  const RE_STEP_BUDGET = 2000000;
  const RE_TOTAL_BUDGET = 6000000;
  const RE_MAX_MATCHES = 5000;
  const RE_MAX_SUBJECT = 100000;
  const RE_MAX_PATTERN = 1000;
  const RE_LINES = "\n\r\u2028\u2029";
  const revStr = (s) => Array.from(s).reverse().join("");
  const reIsWord = (c) => /[A-Za-z0-9_]/.test(c);
  function reFold(c, i, u) {
    if (!i || c === undefined) return c;
    if (u) {
      const lo = c.toLowerCase();
      return lo.length === 1 ? lo : c;
    }
    const up = c.toUpperCase();
    if (up.length !== 1) return c;
    if (c.charCodeAt(0) < 128 && up.charCodeAt(0) >= 128) return c;
    return up;
  }
  const reCpAt = (s, pos, u) => {
    if (!u) return s[pos];
    const c = s.codePointAt(pos);
    return c === undefined ? undefined : String.fromCodePoint(c);
  };
  const reCpStart = (s, pos, u) => {
    if (u && pos >= 2) {
      const a = s.charCodeAt(pos - 1), b = s.charCodeAt(pos - 2);
      if (a >= 0xdc00 && a <= 0xdfff && b >= 0xd800 && b <= 0xdbff) return pos - 2;
    }
    return pos - 1;
  };

  function reParse(pattern, flags) {
    const u = flags.includes("u");
    const src = u ? Array.from(pattern) : pattern.split("");
    let p = 0, slot = 0;
    const names = {};
    const peek = () => src[p];
    const next = () => src[p++];
    const err = (m) => { throw new Error(m + " at pattern offset " + p); };
    function escape(inClass) {
      const c = next();
      if (c === undefined) err("trailing backslash");
      if (c === "d" || c === "D" || c === "w" || c === "W" || c === "s" || c === "S") return { t: "set", set: c };
      if (!inClass && (c === "b" || c === "B")) return { t: "anchor", kind: c };
      if (c === "n") return { t: "char", c: "\n" };
      if (c === "r") return { t: "char", c: "\r" };
      if (c === "t") return { t: "char", c: "\t" };
      if (c === "f") return { t: "char", c: "\f" };
      if (c === "v") return { t: "char", c: "\v" };
      if (c === "0") return { t: "char", c: "\0" };
      if (c === "c") { const x = next(); if (!x || !/[A-Za-z]/.test(x)) err("bad control escape"); return { t: "char", c: String.fromCharCode(x.charCodeAt(0) % 32) }; }
      if (c === "x") { const h = src.slice(p, p + 2).join(""); if (!/^[0-9a-fA-F]{2}$/.test(h)) err("bad \\x escape"); p += 2; return { t: "char", c: String.fromCharCode(parseInt(h, 16)) }; }
      if (c === "u") {
        if (u && peek() === "{") {
          next();
          let h = "";
          while (peek() !== undefined && peek() !== "}") h += next();
          if (next() !== "}" || !/^[0-9a-fA-F]{1,6}$/.test(h) || parseInt(h, 16) > 0x10ffff) err("bad \\u{…} escape");
          return { t: "char", c: String.fromCodePoint(parseInt(h, 16)) };
        }
        const h = src.slice(p, p + 4).join("");
        if (/^[0-9a-fA-F]{4}$/.test(h)) { p += 4; return { t: "char", c: String.fromCharCode(parseInt(h, 16)) }; }
        if (u) err("bad \\u escape");
        return { t: "char", c: "u" };
      }
      if (!inClass && c >= "1" && c <= "9") {
        let n = c;
        while (peek() !== undefined && peek() >= "0" && peek() <= "9" && +n * 10 + +peek() <= slot) n += next();
        if (+n <= slot) return { t: "backref", ref: +n, rev: false };
        if (/^[0-7]+$/.test(n)) return { t: "char", c: String.fromCharCode(parseInt(n, 8) & 0xff) };
        return { t: "char", c: n[0] };
      }
      if (!inClass && c === "k") {
        if (peek() !== "<") err("bad \\k escape");
        next();
        let name = "";
        while (peek() !== undefined && peek() !== ">") name += next();
        if (next() !== ">" || !name) err("bad named backreference");
        return { t: "backref", ref: name, rev: false };
      }
      if (inClass && c === "b") return { t: "char", c: "\b" };
      if (u && !"\\^$.*+?()[]{}|/".includes(c)) err("invalid identity escape \\" + c);
      return { t: "char", c };
    }
    function klass() {
      const neg = peek() === "^";
      if (neg) next();
      const items = [];
      while (peek() !== undefined && peek() !== "]") {
        let lo;
        if (peek() === "\\") { next(); lo = escape(true); }
        else lo = { t: "char", c: next() };
        if (lo.t === "char" && peek() === "-" && src[p + 1] !== undefined && src[p + 1] !== "]") {
          next();
          let hi;
          if (peek() === "\\") { next(); hi = escape(true); }
          else hi = { t: "char", c: next() };
          if (hi.t !== "char") err("invalid class range");
          if (lo.c.codePointAt(0) > hi.c.codePointAt(0)) err("class range out of order");
          items.push({ lo: lo.c, hi: hi.c });
        } else items.push(lo);
      }
      if (next() !== "]") err("unterminated character class");
      return { t: "class", neg, items };
    }
    function atom() {
      const c = peek();
      if (c === undefined) err("unexpected end of pattern");
      if (c === "(") {
        next();
        if (peek() === "?") {
          next();
          const k = peek();
          if (k === ":") { next(); const x = alt(); close(); return { t: "group", x, slot: -1 }; }
          if (k === "=" || k === "!") { next(); const x = alt(); close(); return { t: "look", dir: 1, neg: k === "!", x }; }
          if (k === "<") {
            next();
            const k2 = peek();
            if (k2 === "=" || k2 === "!") { next(); const x = alt(); close(); return { t: "look", dir: -1, neg: k2 === "!", x }; }
            let name = "";
            while (peek() !== undefined && peek() !== ">") name += next();
            if (next() !== ">" || !name || names[name] !== undefined) err("bad or duplicate group name");
            const s = ++slot;
            names[name] = s;
            const x = alt(); close();
            return { t: "group", x, slot: s, name };
          }
          err("unsupported group (?" + (k || ""));
        }
        const s = ++slot;
        const x = alt(); close();
        return { t: "group", x, slot: s };
      }
      if (c === "[") { next(); return klass(); }
      if (c === ".") { next(); return { t: "any" }; }
      if (c === "^" || c === "$") { next(); return { t: "anchor", kind: c }; }
      if (c === "\\") { next(); return escape(false); }
      if (c === ")" || c === "|" || c === "*" || c === "+" || c === "?") err("unexpected " + c);
      next();
      if (u && c.charCodeAt(0) >= 0xd800 && c.charCodeAt(0) <= 0xdbff && peek() !== undefined && peek().charCodeAt(0) >= 0xdc00 && peek().charCodeAt(0) <= 0xdfff) return { t: "char", c: c + next() };
      if (u && c.charCodeAt(0) >= 0xd800 && c.charCodeAt(0) <= 0xdfff) err("lone surrogate in pattern");
      return { t: "char", c };
    }
    function close() { if (next() !== ")") err("unclosed group"); }
    function quant() {
      let x = atom();
      const c = peek();
      let min = 1, max = 1;
      if (c === "*") { next(); min = 0; max = Infinity; }
      else if (c === "+") { next(); min = 1; max = Infinity; }
      else if (c === "?") { next(); min = 0; max = 1; }
      else if (c === "{") {
        const save = p;
        next();
        let a = "";
        while (peek() !== undefined && peek() >= "0" && peek() <= "9") a += next();
        if (a && peek() === "}") { next(); min = max = +a; }
        else if (a && peek() === ",") {
          next();
          let b = "";
          while (peek() !== undefined && peek() >= "0" && peek() <= "9") b += next();
          if (peek() === "}") { next(); min = +a; max = b ? +b : Infinity; }
          else { p = save; return x; }
        } else { p = save; return x; }
        if (max < min) err("quantifier range out of order");
      } else return x;
      if (peek() === "+" || peek() === "?") {
        const lazy = peek() === "?";
        next();
        if (peek() === "+") err("possessive quantifiers are not supported");
        return { t: "rep", x, min, max, lazy };
      }
      return { t: "rep", x, min, max, lazy: false };
    }
    function cat() {
      const xs = [];
      while (peek() !== undefined && peek() !== "|" && peek() !== ")") xs.push(quant());
      return xs.length === 1 ? xs[0] : { t: "cat", xs };
    }
    function alt() {
      const xs = [cat()];
      while (peek() === "|") { next(); xs.push(cat()); }
      return xs.length === 1 ? xs[0] : { t: "alt", xs };
    }
    const ast = alt();
    if (p !== src.length) err("unexpected " + peek());
    return { ast, slots: slot + 1, names, u };
  }

  function reReverse(n) {
    switch (n.t) {
      case "cat": return { t: "cat", xs: n.xs.slice().reverse().map(reReverse) };
      case "alt": return { t: "alt", xs: n.xs.map(reReverse) };
      case "rep": return { t: "rep", x: reReverse(n.x), min: n.min, max: n.max, lazy: n.lazy };
      case "group": return { t: "group", x: reReverse(n.x), slot: n.slot, name: n.name };
      case "look": return { t: "look", dir: -n.dir, neg: n.neg, x: reReverse(n.x) };
      case "backref": return { t: "backref", ref: n.ref, rev: !n.rev };
      case "anchor": return n.kind === "^" ? { t: "anchor", kind: "$" } : n.kind === "$" ? { t: "anchor", kind: "^" } : n;
      default: return n;
    }
  }

  function reCompile(ast) {
    const ops = [];
    let marks = 0;
    const emit = (op) => { ops.push(op); return ops.length - 1; };
    function comp(n) {
      switch (n.t) {
        case "char": case "any": case "class": case "anchor": case "backref": return emit(n);
        case "set": return emit(n);
        case "cat": { for (const x of n.xs) comp(x); return -1; }
        case "group": {
          if (n.slot >= 0) emit({ t: "save", slot: n.slot * 2 });
          comp(n.x);
          if (n.slot >= 0) emit({ t: "save", slot: n.slot * 2 + 1 });
          return -1;
        }
        case "alt": {
          const jumps = [];
          for (let i = 0; i < n.xs.length - 1; i++) {
            const sp = emit({ t: "split", a: 0, b: 0 });
            ops[sp].a = ops.length;
            comp(n.xs[i]);
            jumps.push(emit({ t: "jmp", a: 0 }));
            ops[sp].b = ops.length;
          }
          comp(n.xs[n.xs.length - 1]);
          const end = ops.length;
          for (const j of jumps) ops[j].a = end;
          return -1;
        }
        case "rep": {
          for (let i = 0; i < n.min; i++) comp(n.x);
          if (n.max === Infinity) {
            const sp = emit({ t: "split", a: 0, b: 0 });
            const id = marks++;
            ops[sp].a = ops.length;
            emit({ t: "mark", id });
            comp(n.x);
            const guard = emit({ t: "guard", id, exit: 0, next: sp });
            ops[sp].b = ops.length;
            ops[guard].exit = ops.length;
            if (n.lazy) { const a = ops[sp].a; ops[sp].a = ops[sp].b; ops[sp].b = a; }
          } else {
            const splits = [];
            for (let i = 0; i < n.max - n.min; i++) {
              const sp = emit({ t: "split", a: 0, b: 0 });
              splits.push(sp);
              ops[sp].a = ops.length;
              const id = marks++;
              emit({ t: "mark", id });
              comp(n.x);
              const guard = emit({ t: "guard", id, exit: 0, next: 0 });
              ops[guard].next = ops.length;
              splits.push(guard);
            }
            const end = ops.length;
            for (const idx of splits) {
              const op = ops[idx];
              if (op.t === "split") {
                op.b = end;
                if (n.lazy) { const a = op.a; op.a = op.b; op.b = a; }
              } else op.exit = end;
            }
          }
          return -1;
        }
        case "look": return emit({ t: "look", dir: n.dir, neg: n.neg, sub: reCompile(n.x), subRev: reCompile(reReverse(n.x)) });
        default: throw new Error("unknown node " + n.t);
      }
    }
    comp(ast);
    emit({ t: "match" });
    return ops;
  }

  function reRun(ops, str, start, saves, ctx, budget) {
    const { i, u, m, s } = ctx;
    const len = str.length;
    const stack = [];
    const marks = [];
    let pc = 0, pos = start;
    const revCache = ctx.revCache;
    const cpEq = (a, b) => (i ? reFold(a, i, u) === reFold(b, i, u) : a === b);
    const classHit = (op, c) => {
      let hit = false;
      for (const it of op.items) {
        if (it.t === "set") {
          const set = it.set;
          const low = set.toLowerCase();
          const inSet = low === "d" ? /[0-9]/.test(c) : low === "w" ? /[A-Za-z0-9_]/.test(c) : CLASS_SETS_S.has(c);
          hit = hit || (set === low ? inSet : !inSet);
        } else if (it.lo !== undefined) {
          const cp = c.codePointAt(0);
          const lo = it.lo.codePointAt(0), hi = it.hi.codePointAt(0);
          const f = (x) => (i ? reFold(String.fromCodePoint(x), i, u).codePointAt(0) : x);
          hit = hit || (f(cp) >= f(lo) && f(cp) <= f(hi));
        } else hit = hit || cpEq(c, it.c);
      }
      return op.neg ? !hit : hit;
    };
    for (;;) {
      if (++budget.steps > RE_TOTAL_BUDGET) throw { reBudget: true };
      const op = ops[pc];
      let ok = true;
      switch (op.t) {
        case "char": {
          const c = reCpAt(str, pos, u);
          ok = c !== undefined && cpEq(c, op.c);
          if (ok) pos += c.length;
          break;
        }
        case "any": {
          const c = reCpAt(str, pos, u);
          ok = c !== undefined && (s || !RE_LINES.includes(c));
          if (ok) pos += c.length;
          break;
        }
        case "class": {
          const c = reCpAt(str, pos, u);
          ok = c !== undefined && classHit(op, c);
          if (ok) pos += c.length;
          break;
        }
        case "set": {
          const c = reCpAt(str, pos, u);
          const low = op.set.toLowerCase();
          const inSet = low === "d" ? /[0-9]/.test(c || "") : low === "w" ? /[A-Za-z0-9_]/.test(c || "") : CLASS_SETS_S.has(c || "");
          ok = c !== undefined && (op.set === low ? inSet : !inSet);
          if (ok) pos += c.length;
          break;
        }
        case "anchor": {
          if (op.kind === "^") ok = pos === 0 || (m && RE_LINES.includes(str[pos - 1]));
          else if (op.kind === "$") ok = pos === len || (m && RE_LINES.includes(str[pos]));
          else {
            const before = pos > 0 ? reIsWord(str[reCpStart(str, pos, u)]) : false;
            const after = pos < len ? reIsWord(reCpAt(str, pos, u)) : false;
            ok = op.kind === "b" ? before !== after : before === after;
          }
          break;
        }
        case "save": {
          stack.push({ undo: op.slot, old: saves[op.slot], pc: pc + 1, pos });
          saves[op.slot] = pos;
          pc++;
          continue;
        }
        case "split": {
          stack.push({ pc: op.b, pos, saves: saves.slice() });
          pc = op.a;
          continue;
        }
        case "jmp": pc = op.a; continue;
        case "mark": stack.push({ mark: true, saves: saves.slice(), pos }); marks[op.id] = pos; pc++; continue;
        case "guard": {
          if (marks[op.id] === pos) {
            let f;
            do { f = stack.pop(); } while (f && !f.mark);
            if (f) for (let k = 0; k < saves.length; k++) saves[k] = f.saves[k];
            pc = op.exit;
          } else pc = op.next;
          continue;
        }
        case "backref": {
          const slot = typeof op.ref === "number" ? op.ref : ctx.names[op.ref];
          if (slot === undefined) { ok = false; break; }
          const bs = saves[slot * 2], be = saves[slot * 2 + 1];
          let text = bs >= 0 && be >= bs ? str.slice(bs, be) : "";
          if (op.rev) text = revStr(text);
          let q = pos;
          for (const ch of text) {
            const c = reCpAt(str, q, u);
            if (c === undefined || !cpEq(c, ch)) { ok = false; break; }
            q += c.length;
          }
          if (ok) pos = q;
          break;
        }
        case "look": {
          const copy = saves.slice();
          let r;
          if (op.dir === 1) r = reRun(op.sub, str, pos, copy, ctx, budget);
          else {
            let R = revCache.get(str);
            if (R === undefined) { R = revStr(str); revCache.set(str, R); }
            r = reRun(op.subRev, R, len - pos, copy, ctx, budget);
          }
          const success = r >= 0;
          ok = op.neg ? !success : success;
          if (success) {
            if (op.dir === 1) { for (let k = 2; k < copy.length; k++) if (copy[k] >= 0) saves[k] = copy[k]; }
            else for (let k = 2; k + 1 < copy.length; k += 2) if (copy[k] >= 0) { saves[k] = len - copy[k + 1]; saves[k + 1] = len - copy[k]; }
          }
          break;
        }
        case "match": return pos;
        default: ok = false;
      }
      if (ok) { pc++; continue; }
      let f;
      do { f = stack.pop(); } while (f && f.mark);
      if (!f) return -1;
      if (f.undo !== undefined) { saves[f.undo] = f.old; pc = f.pc; pos = f.pos; }
      else { for (let k = 0; k < saves.length; k++) saves[k] = f.saves[k]; pc = f.pc; pos = f.pos; }
    }
  }
  const CLASS_SETS_S = new Set(" \t\n\r\f\v\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff");

  function reExecAll(pattern, flags, subject) {
    if (typeof pattern !== "string" || pattern.length > RE_MAX_PATTERN) throw new Error("pattern empty or longer than " + RE_MAX_PATTERN + " characters");
    if (!/^[gimsuyd]*$/.test(flags) || new Set(flags).size !== flags.length) throw new Error("flags must be unique letters from g i m s u y d");
    if (flags.includes("v")) throw new Error("the v (unicodeSets) flag is not supported");
    if (subject.length > RE_MAX_SUBJECT) throw new Error("test text longer than " + RE_MAX_SUBJECT + " characters");
    const parsed = reParse(pattern, flags);
    const ops = reCompile(parsed.ast);
    const ctx = { i: flags.includes("i"), u: parsed.u, m: flags.includes("m"), s: flags.includes("s"), names: parsed.names, revCache: new Map() };
    const budget = { steps: 0 };
    const g = flags.includes("g"), y = flags.includes("y");
    const matches = [];
    let from = 0, truncated = false;
    for (;;) {
      let end = -1, saves = null;
      for (let start = from; start <= subject.length; start = parsed.u ? start + (reCpAt(subject, start, true) || " ").length : start + 1) {
        const sv = new Array(parsed.slots * 2).fill(-1);
        sv[0] = start;
        const r = reRun(ops, subject, start, sv, ctx, budget);
        if (r >= 0) { end = r; saves = sv; sv[1] = r; break; }
        if (y) break;
      }
      if (end < 0) break;
      const groups = [];
      for (let k = 1; k < parsed.slots; k++) {
        const gs = saves[k * 2], ge = saves[k * 2 + 1];
        const name = Object.keys(parsed.names).find((n) => parsed.names[n] === k);
        groups.push(gs >= 0 ? { name, index: gs, end: ge, text: subject.slice(gs, ge) } : { name, index: -1, end: -1, text: undefined });
      }
      matches.push({ index: saves[0], end, text: subject.slice(saves[0], end), groups });
      if (matches.length >= RE_MAX_MATCHES) { truncated = true; break; }
      if (!g && !y) break;
      from = end === saves[0] ? (parsed.u ? end + (reCpAt(subject, end, true) || " ").length : end + 1) : end;
      if (from > subject.length) break;
    }
    return { matches, truncated, steps: budget.steps };
  }

  function reExpand(repl, m, subject, hasNames) {
    return String(repl).replace(/\$(\$|&|`|'|<[^>]*>|\d{1,2})/g, (tok, k) => {
      if (k === "$") return "$";
      if (k === "&") return m.text;
      if (k === "`") return subject.slice(0, m.index);
      if (k === "'") return subject.slice(m.end);
      if (k[0] === "<") {
        if (!hasNames) return tok;
        const name = k.slice(1, -1);
        const g = m.groups.find((x) => x.name === name);
        return g && g.text !== undefined ? g.text : "";
      }
      let n = +k;
      if (k.length === 2 && n > m.groups.length) {
        const first = +k[0];
        if (first >= 1 && first <= m.groups.length) {
          const g = m.groups[first - 1];
          return (g && g.text !== undefined ? g.text : "") + k[1];
        }
        return tok;
      }
      if (n === 0 || n > m.groups.length) return tok;
      const g = m.groups[n - 1];
      return g && g.text !== undefined ? g.text : "";
    });
  }

  const regex = {
    test: (pattern, flags, subject) => {
      try {
        const r = reExecAll(pattern, flags || "", String(subject));
        return { ok: true, matches: r.matches, truncated: r.truncated, steps: r.steps };
      } catch (e) {
        return { ok: false, reason: e && e.reBudget ? "backtracking budget exceeded — the pattern may be catastrophic (try simplifying nested quantifiers)" : String(e.message || e) };
      }
    },
    replace: (pattern, flags, subject, repl) => {
      try {
        const s = String(subject);
        const r = reExecAll(pattern, flags || "", s);
        const hasNames = r.matches.some((m) => m.groups.some((g) => g.name));
        let out = "", last = 0, count = 0;
        for (const m of r.matches) {
          out += s.slice(last, m.index) + reExpand(repl, m, s, hasNames);
          last = m.end;
          count++;
        }
        out += s.slice(last);
        return { ok: true, text: out, count, truncated: r.truncated };
      } catch (e) {
        return { ok: false, reason: e && e.reBudget ? "backtracking budget exceeded — the pattern may be catastrophic (try simplifying nested quantifiers)" : String(e.message || e) };
      }
    },
  };

  /* ---------- crypto: symmetric ciphers, implemented locally ----------
   * No WebCrypto: the sandboxed view may not be a secure context, and every
   * algorithm here must work synchronously without a Worker. */

  const be32 = (b, o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
  function joinBytes(...parts) {
    let n = 0;
    for (const p of parts) n += p.length;
    const out = new Uint8Array(n);
    let at = 0;
    for (const p of parts) { out.set(p, at); at += p.length; }
    return out;
  }
  const gfXtime = (a) => { const b = a << 1; return (b & 0x100 ? b ^ 0x11b : b) & 255; };
  const GF_EXP = new Uint8Array(512);
  const GF_LOG = new Uint8Array(256);
  for (let i = 0, g = 1; i < 255; i++) { GF_EXP[i] = g; GF_LOG[g] = i; g = gfXtime(g) ^ g; }
  for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255];
  const gfMul = (a, b) => (a && b ? GF_EXP[(GF_LOG[a] + GF_LOG[b]) % 255] : 0);
  const gfInv = (a) => (a ? GF_EXP[255 - GF_LOG[a]] : 0);
  const rotl8 = (x, n) => ((x << n) | (x >>> (8 - n))) & 255;

  const AES_SBOX = new Uint8Array(256);
  const AES_ISBOX = new Uint8Array(256);
  for (let i = 0; i < 256; i++) {
    const b = gfInv(i);
    const s = (b ^ rotl8(b, 1) ^ rotl8(b, 2) ^ rotl8(b, 3) ^ rotl8(b, 4) ^ 0x63) & 255;
    AES_SBOX[i] = s;
    AES_ISBOX[s] = i;
  }
  const aesSubWord = (w) => ((AES_SBOX[(w >>> 24) & 255] << 24) | (AES_SBOX[(w >>> 16) & 255] << 16) | (AES_SBOX[(w >>> 8) & 255] << 8) | AES_SBOX[w & 255]) >>> 0;

  function aesKey(key) {
    const nk = key.length / 4, nr = nk + 6;
    const w = new Uint32Array(4 * (nr + 1));
    for (let i = 0; i < nk; i++) w[i] = be32(key, i * 4);
    let rcon = 1;
    for (let i = nk; i < w.length; i++) {
      let t = w[i - 1];
      if (i % nk === 0) {
        t = (aesSubWord(((t << 8) | (t >>> 24)) >>> 0) ^ (rcon << 24)) >>> 0;
        rcon = gfXtime(rcon);
      } else if (nk > 6 && i % nk === 4) t = aesSubWord(t);
      w[i] = (w[i - nk] ^ t) >>> 0;
    }
    return { w, nr };
  }
  function aesShiftRows(s, inv) {
    for (let r = 1; r < 4; r++) {
      const row = [s[r], s[r + 4], s[r + 8], s[r + 12]];
      for (let c = 0; c < 4; c++) s[r + 4 * c] = row[(c + (inv ? 4 - r : r)) % 4];
    }
  }
  function aesMixColumns(s, inv) {
    for (let c = 0; c < 4; c++) {
      const o = c * 4, a0 = s[o], a1 = s[o + 1], a2 = s[o + 2], a3 = s[o + 3];
      if (inv) {
        s[o] = gfMul(a0, 14) ^ gfMul(a1, 11) ^ gfMul(a2, 13) ^ gfMul(a3, 9);
        s[o + 1] = gfMul(a0, 9) ^ gfMul(a1, 14) ^ gfMul(a2, 11) ^ gfMul(a3, 13);
        s[o + 2] = gfMul(a0, 13) ^ gfMul(a1, 9) ^ gfMul(a2, 14) ^ gfMul(a3, 11);
        s[o + 3] = gfMul(a0, 11) ^ gfMul(a1, 13) ^ gfMul(a2, 9) ^ gfMul(a3, 14);
      } else {
        s[o] = gfMul(a0, 2) ^ gfMul(a1, 3) ^ a2 ^ a3;
        s[o + 1] = a0 ^ gfMul(a1, 2) ^ gfMul(a2, 3) ^ a3;
        s[o + 2] = a0 ^ a1 ^ gfMul(a2, 2) ^ gfMul(a3, 3);
        s[o + 3] = gfMul(a0, 3) ^ a1 ^ a2 ^ gfMul(a3, 2);
      }
    }
  }
  function aesBlock(block, exp, decrypt) {
    const s = Uint8Array.from(block), nr = exp.nr, w = exp.w;
    const addKey = (round) => {
      for (let c = 0; c < 4; c++) {
        const k = w[round * 4 + c];
        for (let r = 0; r < 4; r++) s[r + 4 * c] ^= (k >>> (24 - 8 * r)) & 255;
      }
    };
    if (decrypt) {
      addKey(nr);
      for (let round = nr - 1; round >= 0; round--) {
        aesShiftRows(s, true);
        for (let i = 0; i < 16; i++) s[i] = AES_ISBOX[s[i]];
        addKey(round);
        if (round > 0) aesMixColumns(s, true);
      }
    } else {
      addKey(0);
      for (let round = 1; round <= nr; round++) {
        for (let i = 0; i < 16; i++) s[i] = AES_SBOX[s[i]];
        aesShiftRows(s, false);
        if (round < nr) aesMixColumns(s, false);
        addKey(round);
      }
    }
    return s;
  }

  /* DES / 3DES (bit-permutation form; small inputs only) */
  const DES_IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7];
  const DES_FP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25];
  const DES_E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1];
  const DES_P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25];
  const DES_PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4];
  const DES_PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32];
  const DES_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
  const DES_S = [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
  ];
  function desBits(bytes) {
    const out = new Uint8Array(bytes.length * 8);
    for (let i = 0; i < bytes.length; i++) for (let j = 0; j < 8; j++) out[i * 8 + j] = (bytes[i] >> (7 - j)) & 1;
    return out;
  }
  function desBytes(bits) {
    const out = new Uint8Array(bits.length / 8);
    for (let i = 0; i < out.length; i++) {
      let v = 0;
      for (let j = 0; j < 8; j++) v = (v << 1) | bits[i * 8 + j];
      out[i] = v;
    }
    return out;
  }
  function desPerm(bits, table) {
    const out = new Uint8Array(table.length);
    for (let i = 0; i < table.length; i++) out[i] = bits[table[i] - 1];
    return out;
  }
  function desRot(bits, n) {
    const out = new Uint8Array(bits.length);
    for (let i = 0; i < bits.length; i++) out[i] = bits[(i + n) % bits.length];
    return out;
  }
  function desKeys(key8) {
    const k = desPerm(desBits(key8), DES_PC1);
    let c = k.subarray(0, 28), d = k.subarray(28, 56);
    const keys = [];
    for (let r = 0; r < 16; r++) {
      c = desRot(c, DES_SHIFTS[r]);
      d = desRot(d, DES_SHIFTS[r]);
      keys.push(desPerm(joinBytes(c, d), DES_PC2));
    }
    return keys;
  }
  function desBlock(block, keys, decrypt) {
    const bits = desPerm(desBits(block), DES_IP);
    let l = bits.subarray(0, 32), r = bits.subarray(32, 64);
    for (let i = 0; i < 16; i++) {
      const k = keys[decrypt ? 15 - i : i];
      const er = desPerm(r, DES_E);
      for (let j = 0; j < 48; j++) er[j] ^= k[j];
      const sb = new Uint8Array(32);
      for (let s = 0; s < 8; s++) {
        const row = (er[s * 6] << 1) | er[s * 6 + 5];
        const col = (er[s * 6 + 1] << 3) | (er[s * 6 + 2] << 2) | (er[s * 6 + 3] << 1) | er[s * 6 + 4];
        const v = DES_S[s][row * 16 + col];
        for (let b = 0; b < 4; b++) sb[s * 4 + b] = (v >> (3 - b)) & 1;
      }
      const f = desPerm(sb, DES_P);
      const next = new Uint8Array(32);
      for (let j = 0; j < 32; j++) next[j] = l[j] ^ f[j];
      l = r;
      r = next;
    }
    return desBytes(desPerm(joinBytes(r, l), DES_FP));
  }
  function des3Block(block, k1, k2, k3, decrypt) {
    return decrypt
      ? desBlock(desBlock(desBlock(block, k3, true), k2, false), k1, true)
      : desBlock(desBlock(desBlock(block, k1, false), k2, true), k3, false);
  }

  /* SM4 (GB/T 32907-2016) */
  const SM4_SBOX = new Uint8Array([
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
  ]);
  const SM4_FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc];
  const SM4_CK = (() => {
    const a = new Uint32Array(32);
    for (let i = 0; i < 32; i++) {
      let v = 0;
      for (let j = 0; j < 4; j++) v = ((v << 8) | (((4 * i + j) * 7) % 256)) >>> 0;
      a[i] = v;
    }
    return a;
  })();
  const sm4Tau = (a) => ((SM4_SBOX[(a >>> 24) & 255] << 24) | (SM4_SBOX[(a >>> 16) & 255] << 16) | (SM4_SBOX[(a >>> 8) & 255] << 8) | SM4_SBOX[a & 255]) >>> 0;
  const sm4L = (b) => (b ^ rotl32(b, 2) ^ rotl32(b, 10) ^ rotl32(b, 18) ^ rotl32(b, 24)) >>> 0;
  const sm4LKey = (b) => (b ^ rotl32(b, 13) ^ rotl32(b, 23)) >>> 0;
  function sm4Keys(key) {
    const k = new Uint32Array(36);
    for (let i = 0; i < 4; i++) k[i] = (be32(key, i * 4) ^ SM4_FK[i]) >>> 0;
    const rk = new Uint32Array(32);
    for (let i = 0; i < 32; i++) {
      k[i + 4] = (k[i] ^ sm4LKey(sm4Tau((k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ SM4_CK[i]) >>> 0))) >>> 0;
      rk[i] = k[i + 4];
    }
    return rk;
  }
  function sm4Block(block, rk, decrypt) {
    const x = new Uint32Array(36);
    for (let i = 0; i < 4; i++) x[i] = be32(block, i * 4);
    for (let i = 0; i < 32; i++) {
      const k = rk[decrypt ? 31 - i : i];
      x[i + 4] = (x[i] ^ sm4L(sm4Tau((x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ k) >>> 0))) >>> 0;
    }
    const out = new Uint8Array(16);
    for (let i = 0; i < 4; i++) {
      const v = x[35 - i];
      out[i * 4] = v >>> 24; out[i * 4 + 1] = (v >>> 16) & 255; out[i * 4 + 2] = (v >>> 8) & 255; out[i * 4 + 3] = v & 255;
    }
    return out;
  }

  /* padding, modes */
  function padData(data, bs, mode) {
    if (mode === "none") {
      if (data.length % bs) throw new Error(`no padding: input must be a multiple of ${bs} bytes (got ${data.length})`);
      return data;
    }
    if (mode === "zero") {
      const out = new Uint8Array(Math.ceil(data.length / bs) * bs);
      out.set(data);
      return out;
    }
    const n = bs - (data.length % bs);
    const out = new Uint8Array(data.length + n);
    out.set(data);
    out.fill(n, data.length);
    return out;
  }
  function unpadData(data, bs, mode) {
    if (mode === "none") return data;
    if (mode === "zero") {
      let end = data.length;
      while (end > 0 && data[end - 1] === 0) end--;
      return data.subarray(0, end);
    }
    if (!data.length || data.length % bs) throw new Error("invalid PKCS7 padding: length is not a multiple of the block size");
    const n = data[data.length - 1];
    if (n < 1 || n > bs) throw new Error(`invalid PKCS7 padding byte: ${n}`);
    for (let i = data.length - n; i < data.length; i++) if (data[i] !== n) throw new Error("invalid PKCS7 padding (wrong key or IV?)");
    return data.subarray(0, data.length - n);
  }
  function ecbCrypt(blockFn, data, decrypt) {
    const out = new Uint8Array(data.length);
    const size = blockFn.size;
    for (let off = 0; off < data.length; off += size) out.set(blockFn(data.subarray(off, off + size), decrypt), off);
    return out;
  }
  function cbcCrypt(blockFn, iv, data, decrypt) {
    const bs = iv.length, out = new Uint8Array(data.length);
    let prev = Uint8Array.from(iv);
    for (let off = 0; off < data.length; off += bs) {
      const blk = data.subarray(off, off + bs);
      if (decrypt) {
        const dec = blockFn(blk, true);
        for (let i = 0; i < bs; i++) out[off + i] = dec[i] ^ prev[i];
        prev = Uint8Array.from(blk);
      } else {
        const x = new Uint8Array(bs);
        for (let i = 0; i < bs; i++) x[i] = blk[i] ^ prev[i];
        prev = blockFn(x, false);
        out.set(prev, off);
      }
    }
    return out;
  }
  function ctrCrypt(blockFn, iv, data) {
    const bs = iv.length, ctr = Uint8Array.from(iv), out = new Uint8Array(data.length);
    for (let off = 0; off < data.length; off += bs) {
      const ks = blockFn(ctr, false);
      const n = Math.min(bs, data.length - off);
      for (let i = 0; i < n; i++) out[off + i] = data[off + i] ^ ks[i];
      for (let i = bs - 1; i >= 0; i--) { ctr[i] = (ctr[i] + 1) & 255; if (ctr[i]) break; }
    }
    return out;
  }

  /* GCM: GHASH over GF(2^128) with a per-key shift table */
  const GCM_R = 0xe1000000000000000000000000000000n;
  function bigOfBytes(b) { let v = 0n; for (const x of b) v = (v << 8n) | BigInt(x); return v; }
  function bytesOfBig(v, n) { const out = new Uint8Array(n); for (let i = 0; i < n; i++) out[n - 1 - i] = Number((v >> BigInt(8 * i)) & 255n); return out; }
  function gcmTable(h) {
    let v = bigOfBytes(h);
    const table = new Array(128);
    for (let i = 0; i < 128; i++) { table[i] = v; v = v & 1n ? (v >> 1n) ^ GCM_R : v >> 1n; }
    return table;
  }
  function gcmMul(table, x) {
    let z = 0n;
    for (let i = 0; i < 16; i++) {
      const b = x[i];
      if (!b) continue;
      for (let j = 0; j < 8; j++) if ((b >> j) & 1) z ^= table[i * 8 + 7 - j];
    }
    return bytesOfBig(z, 16);
  }
  function ghash(table, data) {
    let z = new Uint8Array(16);
    for (let off = 0; off < data.length; off += 16) {
      const x = new Uint8Array(16);
      for (let i = 0; i < 16; i++) x[i] = z[i] ^ data[off + i];
      z = gcmMul(table, x);
    }
    return z;
  }
  function gcmCrypt(blockFn, iv, data, decrypt) {
    const enc = (b) => blockFn(b, false);
    const table = gcmTable(enc(new Uint8Array(16)));
    let j0;
    if (iv.length === 12) { j0 = new Uint8Array(16); j0.set(iv); j0[15] = 1; }
    else {
      const buf = new Uint8Array(Math.ceil(iv.length / 16) * 16 + 16);
      buf.set(iv);
      buf.set(bytesOfBig(BigInt(iv.length) * 8n, 8), buf.length - 8);
      j0 = ghash(table, buf);
    }
    const tagLen = 16;
    if (decrypt && data.length < tagLen) throw new Error("GCM input is shorter than the 16-byte authentication tag");
    const ct = decrypt ? data.subarray(0, data.length - tagLen) : data;
    const counter = Uint8Array.from(j0);
    for (let i = 15; i >= 12; i--) { counter[i] = (counter[i] + 1) & 255; if (counter[i]) break; }
    const body = ctrCrypt(enc, counter, ct);
    const auth = decrypt ? ct : body;
    const padded = new Uint8Array(Math.ceil(auth.length / 16) * 16);
    padded.set(auth);
    const s = ghash(table, joinBytes(padded, new Uint8Array(8), bytesOfBig(BigInt(auth.length) * 8n, 8)));
    const mask = enc(j0);
    const tag = new Uint8Array(16);
    for (let i = 0; i < 16; i++) tag[i] = s[i] ^ mask[i];
    if (decrypt) {
      let diff = 0;
      for (let i = 0; i < 16; i++) diff |= tag[i] ^ data[data.length - tagLen + i];
      if (diff) throw new Error("GCM authentication failed — wrong key/IV or tampered ciphertext");
      return body;
    }
    return joinBytes(body, tag);
  }

  /* stream + classical ciphers */
  function rc4Crypt(key, data) {
    const s = new Uint8Array(256);
    for (let i = 0; i < 256; i++) s[i] = i;
    for (let i = 0, j = 0; i < 256; i++) {
      j = (j + s[i] + key[i % key.length]) & 255;
      const t = s[i]; s[i] = s[j]; s[j] = t;
    }
    const out = new Uint8Array(data.length);
    for (let n = 0, i = 0, j = 0; n < data.length; n++) {
      i = (i + 1) & 255;
      j = (j + s[i]) & 255;
      const t = s[i]; s[i] = s[j]; s[j] = t;
      out[n] = data[n] ^ s[(s[i] + s[j]) & 255];
    }
    return out;
  }
  function xorCrypt(key, data) {
    const out = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i++) out[i] = data[i] ^ key[i % key.length];
    return out;
  }
  function caesarCrypt(data, shift, decrypt) {
    const s = (((decrypt ? -shift : shift) % 26) + 26) % 26;
    const out = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i++) {
      const c = data[i];
      if (c >= 65 && c <= 90) out[i] = 65 + ((c - 65 + s) % 26);
      else if (c >= 97 && c <= 122) out[i] = 97 + ((c - 97 + s) % 26);
      else out[i] = c;
    }
    return out;
  }
  function vigenereCrypt(data, key, decrypt) {
    const shifts = [];
    for (const b of key || []) {
      const c = b >= 97 && b <= 122 ? b - 32 : b;
      if (c >= 65 && c <= 90) shifts.push(c - 65);
    }
    if (!shifts.length) throw new Error("Vigenère key needs at least one letter A-Z");
    const out = new Uint8Array(data.length);
    for (let i = 0, k = 0; i < data.length; i++) {
      const c = data[i], s = shifts[k % shifts.length] * (decrypt ? -1 : 1);
      if (c >= 65 && c <= 90) { out[i] = 65 + (((c - 65 + s) % 26) + 26) % 26; k++; }
      else if (c >= 97 && c <= 122) { out[i] = 97 + (((c - 97 + s) % 26) + 26) % 26; k++; }
      else out[i] = c;
    }
    return out;
  }

  const CIPHERS = {
    aes: { block: 16, keys: [16, 24, 32], modes: ["cbc", "ecb", "ctr", "gcm"], iv: { cbc: 16, ctr: 16, gcm: 12 }, pad: true, max: 1 << 18 },
    sm4: { block: 16, keys: [16], modes: ["cbc", "ecb", "ctr"], iv: { cbc: 16, ctr: 16 }, pad: true, max: 1 << 18 },
    des: { block: 8, keys: [8], modes: ["cbc", "ecb"], iv: { cbc: 8 }, pad: true, max: 1 << 16 },
    "3des": { block: 8, keys: [16, 24], modes: ["cbc", "ecb"], iv: { cbc: 8 }, pad: true, max: 1 << 16 },
    rc4: { stream: true, modes: [], max: 1 << 18 },
    xor: { stream: true, modes: [], max: 1 << 18 },
    rot13: { classical: true, modes: [] },
    caesar: { classical: true, modes: [], shift: true },
    vigenere: { classical: true, modes: [] },
  };

  function crypt(opts) {
    const { dir, alg, key, iv, data, padding = "pkcs7", shift = 0 } = opts;
    const spec = CIPHERS[alg];
    if (!spec) throw new Error("unsupported cipher: " + alg);
    const decrypt = dir === "decrypt";
    if (spec.classical) {
      if (alg === "rot13") return caesarCrypt(data, 13, false);
      if (alg === "caesar") return caesarCrypt(data, Number(shift) || 0, decrypt);
      return vigenereCrypt(data, key, decrypt);
    }
    if (data.length > spec.max) throw new Error(`input too large: ${data.length} bytes (limit ${spec.max} for ${alg})`);
    if (spec.stream) {
      if (!key || !key.length) throw new Error(alg.toUpperCase() + " needs a non-empty key");
      if (key.length > 256) throw new Error("key too long: maximum 256 bytes");
      return alg === "rc4" ? rc4Crypt(key, data) : xorCrypt(key, data);
    }
    if (!key || !spec.keys.includes(key.length)) throw new Error(`${alg.toUpperCase()} key must be ${spec.keys.join(" / ")} bytes (got ${key ? key.length : 0})`);
    const mode = opts.mode || spec.modes[0];
    if (!spec.modes.includes(mode)) throw new Error(`${alg.toUpperCase()} does not support mode ${mode}`);
    const bs = spec.block;
    let blockFn;
    if (alg === "aes") { const exp = aesKey(key); blockFn = (b, d) => aesBlock(b, exp, d); }
    else if (alg === "sm4") { const rk = sm4Keys(key); blockFn = (b, d) => sm4Block(b, rk, d); }
    else if (alg === "des") { const ks = desKeys(key); blockFn = (b, d) => desBlock(b, ks, d); }
    else {
      const k24 = key.length === 16 ? joinBytes(key, key.subarray(0, 8)) : key;
      const k1 = desKeys(k24.subarray(0, 8)), k2 = desKeys(k24.subarray(8, 16)), k3 = desKeys(k24.subarray(16, 24));
      blockFn = (b, d) => des3Block(b, k1, k2, k3, d);
    }
    blockFn.size = bs;
    if (mode === "gcm") {
      if (!iv || !iv.length) throw new Error("GCM needs a nonce/IV (12 bytes recommended)");
      return gcmCrypt(blockFn, iv, data, decrypt);
    }
    if (mode === "ctr") {
      if (!iv || iv.length !== bs) throw new Error(`CTR needs a ${bs}-byte IV/counter (got ${iv ? iv.length : 0})`);
      return ctrCrypt(blockFn, iv, data);
    }
    if (mode === "cbc" && (!iv || iv.length !== bs)) throw new Error(`CBC needs a ${bs}-byte IV (got ${iv ? iv.length : 0})`);
    const run = (buf, dec) => (mode === "cbc" ? cbcCrypt(blockFn, iv, buf, dec) : ecbCrypt(blockFn, buf, dec));
    if (decrypt) {
      if (data.length % bs) throw new Error(`ciphertext length must be a multiple of ${bs} bytes (got ${data.length})`);
      return unpadData(run(data, true), bs, padding);
    }
    return run(padData(data, bs, padding), false);
  }

  const crypto = {
    algorithms: Object.keys(CIPHERS),
    spec: (alg) => CIPHERS[alg] || null,
    crypt,
    randomKey: (alg, size) => {
      const s = CIPHERS[alg];
      if (!s || s.classical) throw new Error("no random key for " + alg);
      const n = size || (s.keys ? s.keys[s.keys.length - 1] : 16);
      if (s.keys && !s.keys.includes(n)) throw new Error("invalid key size for " + alg);
      return randBytes(n);
    },
    randomIv: (alg, mode) => {
      const s = CIPHERS[alg];
      const n = s && s.iv ? s.iv[mode || s.modes[0]] : 0;
      if (!n) throw new Error("no IV for " + alg + " " + mode);
      return randBytes(n);
    },
  };

  /* ---------- export ---------- */

  const Toolbox = { util: { hexOf, fromHex, bytesOf }, hash, base64, url, unicode, ts, password, json, ids, jwt, cron, regex, crypto };
  if (typeof module !== "undefined" && module.exports) module.exports = Toolbox;
  else root.DevToolbox = Toolbox;
})(typeof globalThis !== "undefined" ? globalThis : this);