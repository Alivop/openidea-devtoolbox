import { createRequire } from "node:module";
import crypto from "node:crypto";
const require = createRequire(import.meta.url);
const T = require("../web/tools.js");

let pass = 0, fail = 0;
const eq = (name, got, want) => {
  const g = JSON.stringify(got), w = JSON.stringify(want);
  if (g === w) { pass++; }
  else { fail++; console.error(`FAIL ${name}\n  got:  ${g}\n  want: ${w}`); }
};
const ok = (name, cond, extra = "") => {
  if (cond) pass++;
  else { fail++; console.error(`FAIL ${name} ${extra}`); }
};
const throws = (name, fn) => {
  try { fn(); fail++; console.error(`FAIL ${name} (did not throw)`); }
  catch { pass++; }
};
const B = (s) => new TextEncoder().encode(s);
const hex = (b) => Buffer.from(b).toString("hex");

/* hashes vs known vectors and node crypto */
eq("md5 abc", hex(T.hash.digest("md5", B("abc"))), "900150983cd24fb0d6963f7d28e17f72");
eq("sha1 abc", hex(T.hash.digest("sha-1", B("abc"))), "a9993e364706816aba3e25717850c26c9cd0d89d");
eq("sha256 abc", hex(T.hash.digest("sha-256", B("abc"))), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
eq("sha512 abc", hex(T.hash.digest("sha-512", B("abc"))), "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
eq("sha384 abc", hex(T.hash.digest("sha-384", B("abc"))), "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
eq("sha256 empty", hex(T.hash.digest("sha-256", B(""))), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
/* SM3 GB/T 32905-2016 standard vectors */
eq("sm3 abc", hex(T.hash.digest("sm3", B("abc"))), "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");
eq("sm3 abcd x16", hex(T.hash.digest("sm3", B("abcd".repeat(16)))), "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732");
eq("sm3 empty", hex(T.hash.digest("sm3", B(""))), "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b");
for (const alg of ["md5", "sha-1", "sha-256", "sha-384", "sha-512", "sm3"]) {
  for (const len of [0, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 1000]) {
    const data = crypto.randomBytes(len);
    const nodeAlg = alg === "sha-1" ? "sha1" : alg.replace("-", "");
    eq(`${alg} len${len} vs node`, hex(T.hash.digest(alg, data)), crypto.createHash(nodeAlg).update(data).digest("hex"));
  }
}
/* hmac vs node crypto (oracle) + RFC 4231 case 2 */
eq("hmac-sha256 RFC4231 tc2", hex(T.hash.hmac("sha-256", B("Jefe"), B("what do ya want for nothing?"))), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
for (const alg of ["md5", "sha-1", "sha-256", "sha-384", "sha-512", "sm3"]) {
  for (const keyLen of [0, 10, 64, 65, 128, 200]) {
    const key = crypto.randomBytes(keyLen), msg = crypto.randomBytes(300);
    const nodeAlg = alg === "sha-1" ? "sha1" : alg.replace("-", "");
    eq(`hmac ${alg} key${keyLen} vs node`, hex(T.hash.hmac(alg, key, msg)), crypto.createHmac(nodeAlg, key).update(msg).digest("hex"));
  }
}

/* base64 */
eq("b64 hello", T.base64.encode("hello"), "aGVsbG8=");
eq("b64 utf8", T.base64.encode("中文"), "5Lit5paH");
eq("b64 decode", T.base64.decode("5Lit5paH").text, "中文");
eq("b64 urlsafe", T.base64.encodeBytes(new Uint8Array([251, 255, 191]), true, true), "-_-_");
eq("b64 urlsafe decode", hex(T.base64.decodeBytes("-_-_")), "fbffbf");
eq("b64 no padding", T.base64.encode("hello", { padding: false }), "aGVsbG8");
eq("b64 non-utf8", T.base64.decode("/w==").ok, false);
eq("b64 non-utf8 hex", T.base64.decode("/w==").hex, "ff");
throws("b64 bad char", () => T.base64.decodeBytes("a!cd"));
throws("b64 bad length", () => T.base64.decodeBytes("abcde"));
for (let i = 0; i < 50; i++) {
  const s = crypto.randomBytes(i).toString("base64");
  eq(`b64 roundtrip ${i}`, T.base64.decode(s).hex, hex(Buffer.from(s, "base64")));
}

/* url */
eq("url component", T.url.encode("a b&c=?", "component"), "a%20b%26c%3D%3F");
eq("url form", T.url.encode("a b&c=?", "form"), "a+b%26c%3D%3F");
eq("url uri keeps", T.url.encode("https://x.dev/a b?q=1", "uri"), "https://x.dev/a%20b?q=1");
eq("url decode form", T.url.decode("a+b%26c%3D%3F", "form").text, "a b&c=?");
eq("url decode bad", T.url.decode("%E0%A4%A", "component").ok, false);
eq("url utf8 roundtrip", T.url.decode(T.url.encode("中文 😀", "component"), "component").text, "中文 😀");

/* unicode */
eq("uni js", T.unicode.escape("中A😀", "js"), "\\u4E2DA\\uD83D\\uDE00");
eq("uni es6", T.unicode.escape("中A😀", "es6"), "\\u{4E2D}A\\u{1F600}");
eq("uni html", T.unicode.escape("中A😀", "html"), "&#x4E2D;A&#x1F600;");
eq("uni unescape js", T.unicode.unescape("\\u4E2DA\\uD83D\\uDE00"), "中A😀");
eq("uni unescape es6", T.unicode.unescape("\\u{4E2D}A\\u{1F600}"), "中A😀");
eq("uni unescape html", T.unicode.unescape("&#x4E2D;A&#128512;"), "中A😀");
eq("uni codepoints", T.unicode.codepoints("中A😀").map((c) => c.cp), ["U+4E2D", "U+0041", "U+1F600"]);
eq("uni utf8 bytes", T.unicode.codepoints("中")[0].utf8, "e4b8ad");

/* timestamp */
eq("ts seconds", T.ts.parse("1700000000"), { ms: 1700000000000, unit: "s" });
eq("ts ms", T.ts.parse("1700000000000").unit, "ms");
eq("ts us", T.ts.parse("1700000000000000").unit, "us");
eq("ts ns", T.ts.parse("1700000000000000000"), { ms: 1700000000000, unit: "ns" });
eq("ts utc fmt", T.ts.formats(1700000000000).utc, "2023-11-14 22:13:20 UTC");
eq("ts iso", T.ts.formats(1700000000000).iso, "2023-11-14T22:13:20.000Z");
eq("ts fractional", T.ts.parse("1700000000.5").ms, 1700000000500);
throws("ts garbage", () => T.ts.parse("not-a-date"));
eq("ts fromDate utc", T.ts.fromDate("2023-11-14 22:13:20", true), 1700000000000);

/* password */
const pw = T.password.generate({ length: 24, symbols: true });
eq("pw length", pw.text.length, 24);
ok("pw classes", /[a-z]/.test(pw.text) && /[A-Z]/.test(pw.text) && /[0-9]/.test(pw.text) && /[^a-zA-Z0-9]/.test(pw.text));
ok("pw entropy", pw.entropyBits > 100);
const pw2 = T.password.generate({ length: 32, excludeAmbiguous: true });
ok("pw no ambiguous", !/[Il1O0o]/.test(pw2.text));
const pw3 = T.password.generate({ length: 8, upper: false, digits: false, symbols: false });
ok("pw lower only", /^[a-z]{8}$/.test(pw3.text));

/* json */
eq("json format", T.json.format('{"b":1,"a":[1,2]}', { indent: 2 }).text, '{\n  "b": 1,\n  "a": [\n    1,\n    2\n  ]\n}');
eq("json sort", T.json.format('{"b":1,"a":2}', { sortKeys: true, indent: 0 }).text, '{"a":2,"b":1}');
eq("json minify", T.json.minify('{ "a" : 1 }').text, '{"a":1}');
const bad = T.json.format('{"a":}');
ok("json error pos", !bad.ok && bad.line === 1 && bad.column === 6, JSON.stringify(bad));
ok("json minify bad", !T.json.minify("{").ok);

/* ids */
const u4 = T.ids.uuidv4();
ok("uuidv4 shape", /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(u4), u4);
const u7 = T.ids.uuidv7();
ok("uuidv7 shape", /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(u7), u7);
const u7ms = parseInt(u7.replace(/-/g, "").slice(0, 12), 16);
ok("uuidv7 time", Math.abs(u7ms - Date.now()) < 2000);
eq("nanoid len", T.ids.nanoid(21).length, 21);
ok("nanoid alphabet", /^[A-Za-z0-9_-]{21}$/.test(T.ids.nanoid(21)));
const sf = T.ids.snowflake({ machine: 5 });
const dec = T.ids.snowflakeDecode(sf);
eq("snowflake machine", dec.machine, 5);
ok("snowflake time", Math.abs(new Date(dec.time).getTime() - Date.now()) < 2000);
ok("snowflake unique", new Set(Array.from({ length: 200 }, () => T.ids.snowflake())).size === 200);
ok("objectid", /^[0-9a-f]{24}$/.test(T.ids.objectid()));

/* jwt */
const rfc = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const parsed = T.jwt.parse(rfc);
eq("jwt rfc alg", parsed.alg, "HS256");
eq("jwt rfc iss", parsed.payload.iss, "joe");
eq("jwt rfc exp status", parsed.times.find((t) => t.claim === "exp").status, "expired");
const token = T.jwt.sign('{"sub":"123","name":"中文"}', "secret", "HS256");
eq("jwt verify ok", T.jwt.verify(token, "secret"), { ok: true });
eq("jwt verify wrong", T.jwt.verify(token, "secret2").ok, false);
const [h, p, s] = token.split(".");
const nodeSig = crypto.createHmac("sha256", "secret").update(`${h}.${p}`).digest("base64url");
eq("jwt sig vs node", s, nodeSig);
for (const alg of ["HS384", "HS512"]) {
  const t = T.jwt.sign('{"a":1}', "k", alg);
  eq(`jwt ${alg} verify`, T.jwt.verify(t, "k"), { ok: true });
  const [hh, pp, ss] = t.split(".");
  eq(`jwt ${alg} vs node`, ss, crypto.createHmac(alg.replace("HS", "sha"), "k").update(`${hh}.${pp}`).digest("base64url"));
}
throws("jwt bad parts", () => T.jwt.parse("a.b"));
throws("jwt sign bad payload", () => T.jwt.sign("{nope", "k"));
eq("jwt rs parse only", T.jwt.verify(rfc.replace("HS256", "RS256"), "k").ok, false);

/* cron */
const from = new Date(2026, 0, 1, 0, 0, 0).getTime();
eq("cron */5", T.cron.next("*/5 * * * *", from, 3).runs.map((d) => T.ts.fmt(d, false)), ["2026-01-01 00:05:00", "2026-01-01 00:10:00", "2026-01-01 00:15:00"]);
eq("cron feb29", T.cron.next("0 0 29 2 *", from, 1).runs.map((d) => T.ts.fmt(d, false)), ["2028-02-29 00:00:00"]);
eq("cron weekly", T.cron.next("0 12 * * MON", from, 1).runs.map((d) => T.ts.fmt(d, false)), ["2026-01-05 12:00:00"]);
eq("cron dom/dow OR", T.cron.next("0 0 13 * FRI", from, 1).runs.map((d) => T.ts.fmt(d, false)), ["2026-01-02 00:00:00"]);
eq("cron 6-field", T.cron.next("*/10 * * * * *", from, 3).runs.map((d) => d.getSeconds()), [10, 20, 30]);
eq("cron names", T.cron.next("0 0 1 JAN *", from, 1).runs.map((d) => T.ts.fmt(d, false)), ["2027-01-01 00:00:00"]);
eq("cron range step", T.cron.next("0 9-17/2 * * *", from, 4).runs.map((d) => d.getHours()), [9, 11, 13, 15]);
throws("cron minute 60", () => T.cron.parse("60 * * * *"));
throws("cron L unsupported", () => T.cron.parse("0 0 L * *"));
throws("cron 4 fields", () => T.cron.parse("* * * *"));
eq("cron describe en", T.cron.describe("*/5 * * * *", "en"), "Every 5 minutes");
eq("cron describe zh", T.cron.describe("0 12 * * MON", "zh"), "每周一 12:00");
eq("cron describe daily", T.cron.describe("30 8 * * *", "en"), "Daily at 08:30");
ok("cron impossible truncates", T.cron.next("0 0 31 2 *", from, 1).truncated);

/* ---------- regex engine vs native RegExp ---------- */
const norm = (m) => ({
  index: m.index,
  text: m[0],
  groups: m.slice(1).map((g) => (g === undefined ? null : g)),
  names: m.groups ? Object.entries(m.groups).map(([k, v]) => [k, v === undefined ? null : v]) : [],
});
function nativeMatches(pattern, flags, s) {
  const re = new RegExp(pattern, flags);
  const out = [];
  if (flags.includes("g")) {
    for (const m of s.matchAll(re)) out.push(norm(m));
  } else if (flags.includes("y")) {
    re.lastIndex = 0;
    for (;;) {
      const m = re.exec(s);
      if (!m) break;
      out.push(norm(m));
      if (m[0] === "") re.lastIndex += flags.includes("u") ? (s.codePointAt(re.lastIndex - 1) > 0xffff ? 2 : 1) : 1;
      if (re.lastIndex > s.length) break;
    }
  } else {
    const m = re.exec(s);
    if (m) out.push(norm(m));
  }
  return out;
}
const oursNorm = (r) => r.matches.map((m) => ({
  index: m.index,
  text: m.text,
  groups: m.groups.map((g) => (g.text === undefined ? null : g.text)),
  names: m.groups.filter((g) => g.name).map((g) => [g.name, g.text === undefined ? null : g.text]),
}));
const CASES = [
  ["a+", "", "baaa"], ["a*", "g", "bab"], ["(a|ab)+", "", "abab"], ["a|ab", "g", "ab"],
  ["(a+)(b?)", "g", "aab aab"], ["(?<y>\\d{4})-(?<m>\\d{2})", "", "2026-11"],
  ["\\b\\w+\\b", "g", "hello world_42 x"], ["^a.*b$", "m", "a1\na2b\nxx"],
  ["a.c", "s", "a\nc"], ["[a-z]+", "i", "AbC dEf"], ["[^0-9]+", "g", "a1b22c"],
  ["(a)(b)\\2\\1", "", "abba abab"], ["(?=(a+))a", "g", "aaa"], ["(?<=(a|ab))b", "", "ab"],
  ["(?<=(a+))b", "", "aaab"], ["(?<!a)b", "g", "ab cb"], ["a(?=b)", "g", "ab ac"],
  ["a(?!b)", "g", "ab ac"], ["\\u{1F600}", "u", "x😀y"], ["[\\u{1F600}-\\u{1F602}]", "u", "x😀"],
  [".", "gu", "a😀b"], ["(?:)", "gu", "😀a"], ["ß", "iu", "ẞ"], ["K", "iu", "k"],
  ["ß", "i", "ẞ"], ["[a-z]", "iu", "KK"], ["\\bé", "u", "xé é"],
  ["a{2,4}", "g", "a aa aaa aaaaa"], ["a{2,4}?", "g", "aaaa"], ["a+?", "g", "aaa"],
  ["(a+?)+", "", "aaa"], ["colou?r", "gi", "color Colour COLOUR"],
  ["\\d+", "g", "a12b345"], ["\\S+", "g", "a b\tc"], ["[\\w-]+", "g", "ab-cd ef"],
  ["(foo|foobar)bar", "", "foobarbar fooobar"], ["x(x?){12}y", "", "x".repeat(13) + "y"],
  ["^$", "gm", "a\n\nb"], ["a$", "m", "a\nb"], ["\\A", "", "A"],
  ["a|", "g", "bab"], ["(|a)", "g", "bab"], ["(a*)*", "", "aa"],
  ["(a|a)*b", "", "aaab"], ["\\1", "", "\x01"], ["(a)\\1", "i", "aA"],
  ["(?<n>a)\\k<n>", "", "aa"], ["a.*?c", "g", "abcabc"], ["<(.+?)>", "g", "<a><bb>"],
  ["[\\s\\S]+", "", "a\nb"], ["a", "y", "aa"], ["a", "y", "ba"], ["a", "gy", "aab"],
  ["a(d)?", "d", "ad"], ["", "g", "ab"], ["(?<=^)a", "m", "b\na"],
  ["(?=(?=(a)))a", "", "a"], ["(?<=(a(?=b)))b", "", "ab"], ["(?:)*", "g", "ab"],
  ["(a*)*", "g", "bb"], ["[]]", "", "]"], ["[^]", "g", "a\n"], ["[\\]]+", "g", "a]b]]"],
  ["a{2}", "g", "aaa"], ["a{2,}", "g", "aaa"], ["\\x41\\u0042", "", "AB"],
  ["[a-z][0-9]", "gi", "a1 B2 c3"], ["(?i)a", "", "a"],
];
for (const [p, f, s] of CASES) {
  let want;
  try { want = nativeMatches(p, f, s); } catch { want = "throw"; }
  const got = T.regex.test(p, f, s);
  if (want === "throw") { ok(`regex invalid ${p}/${f}`, !got.ok, got.reason); continue; }
  ok(`regex match ${p}/${f}`, got.ok && JSON.stringify(oursNorm(got)) === JSON.stringify(want), got.ok ? JSON.stringify(oursNorm(got)) + " want " + JSON.stringify(want) : got.reason);
}
const REPL = [
  ["(\\w+)\\s(\\w+)", "", "hello world", "$2 $1"],
  ["a", "g", "banana", "[$&]"],
  ["a", "g", "banana", "$$"],
  ["(a)(b)", "", "ab", "$<x>"],
  ["(a)(b)", "", "ab", "$<a>$<b>"],
  ["a", "", "banana", "$`|$'"],
  ["(a)", "g", "aa", "$1$1"],
  ["(a)", "g", "aa", "$12"],
  ["a", "g", "aaa", "$01"],
  ["a", "g", "banana", "X"],
  ["(a+)", "", "aaa", "[$1]"],
];
for (const [p, f, s, r] of REPL) {
  const want = s.replace(new RegExp(p, f), r);
  const got = T.regex.replace(p, f, s, r);
  ok(`regex replace ${p} ${r}`, got.ok && got.text === want, got.ok ? got.text + " want " + want : got.reason);
}
for (const [p, f, s] of [["(a+)+$", "", "a".repeat(28) + "!"], ["(a|aa)*$", "", "a".repeat(24) + "!"], ["(x+x+)+y", "", "x".repeat(20) + "z"]]) {
  const t0 = Date.now();
  const got = T.regex.test(p, f, s);
  const ms = Date.now() - t0;
  ok(`regex bomb budget ${p}`, !got.ok && /budget/.test(got.reason) && ms < 3000, `${ms}ms ${got.reason || ""}`);
}
for (const [p, f] of [["(", ""], ["[z-a]", ""], ["a{2,1}", ""], ["(?<n>a)(?<n>b)", ""], ["\\p{L}", "u"], ["a", "gg"], ["a", "v"], ["a**", ""]]) {
  ok(`regex rejects ${p}/${f}`, !T.regex.test(p, f, "a").ok);
}
ok("regex subject cap", !T.regex.test("a", "", "x".repeat(100001)).ok);

/* crypto: known vectors + differential tests against node:crypto (OpenSSL) */
const H = (s) => T.util.fromHex(s);
let seed = 20261116;
const rnd = (n) => {
  const b = Buffer.alloc(n);
  for (let i = 0; i < n; i++) { seed = (seed * 1103515245 + 12345) & 0x7fffffff; b[i] = (seed >>> 16) & 255; }
  return b;
};
const nodeEnc = (name, key, iv, data, autoPad = true) => {
  const gcm = name.endsWith("gcm");
  const c = crypto.createCipheriv(name, key, iv);
  if (!gcm) c.setAutoPadding(autoPad);
  const out = Buffer.concat([c.update(data), c.final()]);
  return gcm ? Buffer.concat([out, c.getAuthTag()]) : out;
};
const nodeDec = (name, key, iv, data, autoPad = true) => {
  const gcm = name.endsWith("gcm");
  const c = crypto.createDecipheriv(name, key, iv);
  if (gcm) c.setAuthTag(data.subarray(data.length - 16));
  else c.setAutoPadding(autoPad);
  return Buffer.concat([c.update(gcm ? data.subarray(0, data.length - 16) : data), c.final()]);
};
const ours = (dir, alg, mode, key, iv, data, padding = "pkcs7") =>
  T.crypto.crypt({ dir, alg, mode, key, iv, data, padding });

/* FIPS-197 / GB-T 32907-2016 single-block vectors */
eq("aes-128 fips197", hex(ours("encrypt", "aes", "ecb", H("000102030405060708090a0b0c0d0e0f"), null, H("00112233445566778899aabbccddeeff"), "none")), "69c4e0d86a7b0430d8cdb78070b4c55a");
eq("aes-192 fips197", hex(ours("encrypt", "aes", "ecb", H("000102030405060708090a0b0c0d0e0f1011121314151617"), null, H("00112233445566778899aabbccddeeff"), "none")), "dda97ca4864cdfe06eaf70a0ec0d7191");
eq("aes-256 fips197", hex(ours("encrypt", "aes", "ecb", H("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"), null, H("00112233445566778899aabbccddeeff"), "none")), "8ea2b7ca516745bfeafc49904b496089");
eq("aes-128 fips197 inverse", hex(ours("decrypt", "aes", "ecb", H("000102030405060708090a0b0c0d0e0f"), null, H("69c4e0d86a7b0430d8cdb78070b4c55a"), "none")), "00112233445566778899aabbccddeeff");
eq("sm4 gbt32907", hex(ours("encrypt", "sm4", "ecb", H("0123456789abcdeffedcba9876543210"), null, H("0123456789abcdeffedcba9876543210"), "none")), "681edf34d206965e86b3e94f536e4246");
eq("sm4 gbt32907 inverse", hex(ours("decrypt", "sm4", "ecb", H("0123456789abcdeffedcba9876543210"), null, H("681edf34d206965e86b3e94f536e4246"), "none")), "0123456789abcdeffedcba9876543210");

/* AES / SM4 / DES / 3DES vs OpenSSL, pkcs7 + none */
function refName(alg, mode, key) {
  if (alg === "aes") return { name: `aes-${key.length * 8}-${mode}`, key };
  if (alg === "sm4") return { name: `sm4-${mode}`, key };
  const k = alg === "des" ? Buffer.concat([key, key, key]) : key.length === 16 ? Buffer.concat([key, key.subarray(0, 8)]) : key;
  return { name: mode === "ecb" ? "des-ede3" : `des-ede3-${mode}`, key: k };
}
const MATRIX = [
  ["aes", [16, 24, 32], ["cbc", "ecb", "ctr"], [0, 1, 15, 16, 17, 64, 1000]],
  ["sm4", [16], ["cbc", "ecb", "ctr"], [0, 1, 15, 16, 17, 64]],
  ["des", [8], ["cbc", "ecb"], [0, 1, 7, 8, 9, 31]],
  ["3des", [16, 24], ["cbc", "ecb"], [0, 1, 7, 8, 9, 31]],
];
for (const [alg, keySizes, modes, lens] of MATRIX) {
  for (const ks of keySizes) for (const mode of modes) for (const len of lens) {
    const key = rnd(ks), data = rnd(len);
    const spec = T.crypto.spec(alg);
    const iv = mode === "ecb" ? null : rnd(spec.iv[mode]);
    const ref = refName(alg, mode, key);
    for (const padding of mode === "ctr" ? ["pkcs7"] : ["pkcs7", "none"]) {
      if (padding === "none" && len % spec.block) continue;
      const tag = `${alg}-${ks * 8}-${mode}-${padding}-${len}`;
      const want = nodeEnc(ref.name, ref.key, iv, data, padding === "pkcs7");
      const got = ours("encrypt", alg, mode, key, iv, data, padding);
      eq("enc " + tag, hex(got), hex(want));
      eq("dec " + tag, hex(ours("decrypt", alg, mode, key, iv, got, padding)), hex(data));
      eq("dec-node " + tag, hex(nodeDec(ref.name, ref.key, iv, got, padding === "pkcs7")), hex(data));
    }
  }
}

/* AES-GCM: ciphertext||tag, several nonce lengths, empty AAD */
for (const ks of [16, 24, 32]) for (const ivLen of [12, 8, 16, 20]) for (const len of [0, 1, 16, 60, 1000]) {
  const key = rnd(ks), iv = rnd(ivLen), data = rnd(len);
  const name = `aes-${ks * 8}-gcm`;
  const tag = `gcm-${ks * 8}-iv${ivLen}-${len}`;
  const want = nodeEnc(name, key, iv, data);
  const got = ours("encrypt", "aes", "gcm", key, iv, data);
  eq("enc " + tag, hex(got), hex(want));
  eq("dec " + tag, hex(ours("decrypt", "aes", "gcm", key, iv, got)), hex(data));
  eq("dec-node " + tag, hex(nodeDec(name, key, iv, got)), hex(data));
}
{
  const key = rnd(16), iv = rnd(12), data = B("attack at dawn");
  const ct = ours("encrypt", "aes", "gcm", key, iv, data);
  const bad = Uint8Array.from(ct); bad[3] ^= 1;
  throws("gcm tampered ciphertext", () => ours("decrypt", "aes", "gcm", key, iv, bad));
  throws("gcm wrong key", () => ours("decrypt", "aes", "gcm", rnd(16), iv, ct));
  throws("gcm wrong iv", () => ours("decrypt", "aes", "gcm", key, rnd(12), ct));
  throws("gcm short input", () => ours("decrypt", "aes", "gcm", key, iv, ct.subarray(0, 8)));
  let err = "";
  try { ours("decrypt", "aes", "gcm", key, iv, bad); } catch (e) { err = e.message; }
  ok("gcm auth message", /authentication/.test(err), err);
}

/* zero padding interoperates with raw OpenSSL (no auto padding) */
for (const alg of ["aes", "sm4", "3des"]) {
  const spec = T.crypto.spec(alg);
  const key = rnd(spec.keys[spec.keys.length - 1]), iv = rnd(spec.block), data = B("zero padded");
  const padded = Buffer.alloc(Math.ceil(data.length / spec.block) * spec.block);
  padded.set(data);
  const ref = refName(alg, "cbc", key);
  eq(`zero pad ${alg}`, hex(ours("encrypt", alg, "cbc", key, iv, data, "zero")), hex(nodeEnc(ref.name, ref.key, iv, padded, false)));
  eq(`zero unpad ${alg}`, Buffer.from(ours("decrypt", alg, "cbc", key, iv, ours("encrypt", alg, "cbc", key, iv, data, "zero"), "zero")).toString(), "zero padded");
}

/* RC4 / XOR / classical */
eq("rc4 Key/Plaintext", hex(ours("encrypt", "rc4", "", B("Key"), null, B("Plaintext"))), "bbf316e8d940af0ad3");
eq("rc4 Wiki/pedia", hex(ours("encrypt", "rc4", "", B("Wiki"), null, B("pedia"))), "1021bf0420");
eq("rc4 Secret/Attack at dawn", hex(ours("encrypt", "rc4", "", B("Secret"), null, B("Attack at dawn"))), "45a01f645fc35b383552544b9bf5");
eq("rc4 decrypt", Buffer.from(ours("decrypt", "rc4", "", B("Key"), null, H("bbf316e8d940af0ad3"))).toString(), "Plaintext");
eq("xor bytes", hex(ours("encrypt", "xor", "", H("0102"), null, B("abc"))), hex(Buffer.from([0x61 ^ 1, 0x62 ^ 2, 0x63 ^ 1])));
eq("xor round trip", Buffer.from(ours("decrypt", "xor", "", B("密钥 key"), null, ours("encrypt", "xor", "", B("密钥 key"), null, B("hello 世界")))).toString(), "hello 世界");
eq("caesar 3", Buffer.from(T.crypto.crypt({ dir: "encrypt", alg: "caesar", shift: 3, data: B("Hello, World!") })).toString(), "Khoor, Zruog!");
eq("caesar decrypt", Buffer.from(T.crypto.crypt({ dir: "decrypt", alg: "caesar", shift: 3, data: B("Khoor, Zruog!") })).toString(), "Hello, World!");
eq("caesar 26 identity", Buffer.from(T.crypto.crypt({ dir: "encrypt", alg: "caesar", shift: 26, data: B("abc XYZ") })).toString(), "abc XYZ");
eq("caesar negative", Buffer.from(T.crypto.crypt({ dir: "encrypt", alg: "caesar", shift: -1, data: B("abc") })).toString(), "zab");
eq("rot13", Buffer.from(ours("encrypt", "rot13", "", null, null, B("Hello, World!"))).toString(), "Uryyb, Jbeyq!");
eq("rot13 self-inverse", Buffer.from(ours("encrypt", "rot13", "", null, null, B("Uryyb, Jbeyq!"))).toString(), "Hello, World!");
eq("vigenere LEMON", Buffer.from(ours("encrypt", "vigenere", "", B("LEMON"), null, B("ATTACKATDAWN"))).toString(), "LXFOPVEFRNHR");
eq("vigenere decrypt", Buffer.from(ours("decrypt", "vigenere", "", B("LEMON"), null, B("LXFOPVEFRNHR"))).toString(), "ATTACKATDAWN");
eq("vigenere keeps non-letters", Buffer.from(ours("encrypt", "vigenere", "", B("LEMON"), null, B("ATTACK AT DAWN"))).toString(), "LXFOPV EF RNHR");
eq("vigenere lowercase key", Buffer.from(ours("encrypt", "vigenere", "", B("lemon"), null, B("attackatdawn"))).toString(), "lxfopvefrnhr");

/* UTF-8 payloads and random-key helpers */
for (const alg of ["aes", "sm4", "3des", "rc4"]) {
  const spec = T.crypto.spec(alg);
  const key = T.crypto.randomKey(alg);
  const mode = spec.modes[0] || "";
  const iv = mode === "ecb" || !mode ? null : T.crypto.randomIv(alg, mode);
  const text = "混合 text 😀 — 1234567890";
  const ct = ours("encrypt", alg, mode, key, iv, B(text));
  eq(`utf8 round trip ${alg}`, Buffer.from(ours("decrypt", alg, mode, key, iv, ct)).toString(), text);
  ok(`randomKey ${alg}`, !spec.keys || spec.keys.includes(key.length));
  if (iv) ok(`randomIv ${alg}`, iv.length === spec.iv[mode]);
}
eq("aes-256 random key size", T.crypto.randomKey("aes").length, 32);
eq("gcm random iv size", T.crypto.randomIv("aes", "gcm").length, 12);

/* option validation */
throws("aes bad key size", () => ours("encrypt", "aes", "cbc", rnd(15), rnd(16), B("x")));
throws("aes missing key", () => T.crypto.crypt({ dir: "encrypt", alg: "aes", mode: "cbc", data: B("x") }));
throws("cbc bad iv", () => ours("encrypt", "aes", "cbc", rnd(16), rnd(15), B("x")));
throws("ctr missing iv", () => T.crypto.crypt({ dir: "encrypt", alg: "aes", mode: "ctr", key: rnd(16), data: B("x") }));
throws("gcm missing iv", () => T.crypto.crypt({ dir: "encrypt", alg: "aes", mode: "gcm", key: rnd(16), data: B("x") }));
throws("unsupported mode", () => ours("encrypt", "aes", "cfb", rnd(16), rnd(16), B("x")));
throws("unsupported alg", () => T.crypto.crypt({ dir: "encrypt", alg: "rsa", data: B("x") }));
throws("none padding ragged", () => ours("encrypt", "aes", "ecb", rnd(16), null, rnd(15), "none"));
throws("ragged ciphertext", () => ours("decrypt", "aes", "cbc", rnd(16), rnd(16), rnd(15)));
throws("rc4 empty key", () => T.crypto.crypt({ dir: "encrypt", alg: "rc4", key: new Uint8Array(0), data: B("x") }));
throws("rc4 long key", () => T.crypto.crypt({ dir: "encrypt", alg: "rc4", key: rnd(257), data: B("x") }));
throws("vigenere numeric key", () => ours("encrypt", "vigenere", "", B("123"), null, B("abc")));
throws("des input cap", () => ours("encrypt", "des", "ecb", rnd(8), null, rnd((1 << 16) + 1)));
throws("aes input cap", () => ours("encrypt", "aes", "ctr", rnd(16), rnd(16), rnd((1 << 18) + 1)));
{
  const k = H("000102030405060708090a0b0c0d0e0f");
  const ct = ours("encrypt", "aes", "ecb", k, null, new Uint8Array(16), "none");
  throws("bad padding byte", () => ours("decrypt", "aes", "ecb", k, null, ct));
}
{
  const key = rnd(16), iv = rnd(16);
  const ct = ours("encrypt", "aes", "cbc", key, iv, B("hello world"));
  const other = rnd(16);
  let threw = false, plain = null;
  try { plain = Buffer.from(ours("decrypt", "aes", "cbc", other, iv, ct)).toString(); } catch { threw = true; }
  ok("wrong key rejected", threw || plain !== "hello world", plain);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);