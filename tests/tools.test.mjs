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
for (const alg of ["md5", "sha-1", "sha-256", "sha-384", "sha-512"]) {
  for (const len of [0, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 1000]) {
    const data = crypto.randomBytes(len);
    const nodeAlg = alg === "sha-1" ? "sha1" : alg.replace("-", "");
    eq(`${alg} len${len} vs node`, hex(T.hash.digest(alg, data)), crypto.createHash(nodeAlg).update(data).digest("hex"));
  }
}
/* hmac vs node crypto (oracle) + RFC 4231 case 2 */
eq("hmac-sha256 RFC4231 tc2", hex(T.hash.hmac("sha-256", B("Jefe"), B("what do ya want for nothing?"))), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
for (const alg of ["md5", "sha-1", "sha-256", "sha-384", "sha-512"]) {
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

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);