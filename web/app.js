/* UI wiring for the toolbox view. Pure local logic lives in tools.js; this
   file only touches the DOM. Works with or without the IDE bridge. */
(function () {
  const T = window.DevToolbox;
  const $ = (id) => document.getElementById(id);

  const I18N = {
    en: {
      title: "Developer Toolbox",
      "tool.ts": "Timestamp", "tool.password": "Password", "tool.json": "JSON", "tool.ids": "IDs",
      "tool.base64": "Base64", "tool.url": "URL", "tool.unicode": "Unicode", "tool.jwt": "JWT",
      "tool.cron": "Cron", "tool.hash": "Hash", "tool.regex": "Regex", "tool.crypto": "Crypto",
      now: "Now", convert: "Convert", copy: "Copy", clear: "Clear", generate: "Generate", format: "Format",
      minify: "Minify", encode: "Encode", decode: "Decode", escape: "Escape", unescape: "Unescape",
      parse: "Parse", verify: "Verify", sign: "Sign", preview: "Preview", compute: "Compute",
      copied: "Copied", copyFail: "Copy failed — select the text and press ⌘/Ctrl+C",
      "theme.dark": "Dark", "theme.light": "Light",
      "ts.input": "Timestamp or date", "ts.ph": "1700000000 / 1700000000000 / 2026-01-01 00:00:00",
      "ts.local": "Local", "ts.utc": "UTC", "ts.seconds": "Seconds", "ts.milliseconds": "Milliseconds",
      "ts.unit": "Detected unit: {0}",
      "pw.length": "Length", "pw.count": "Count", "pw.ambiguous": "No look-alikes (Il1O0o)",
      "pw.entropy": "≈ {0} bits of entropy", "pw.entropyEach": "≈ {0} bits each",
      "json.ph": '{"paste":"JSON here"}', "json.indent": "Indent", "json.sort": "Sort keys",
      "json.errPos": "Line {0}, column {1}: {2}",
      "ids.count": "Count", "ids.size": "NanoID length", "ids.machine": "Machine",
      "ids.decodePh": "Snowflake ID to decode", "ids.decode": "Decode",
      "ids.time": "Time", "ids.sequence": "Sequence",
      "b64.ph": "Text or Base64",
      "url.ph": "Text or percent-encoded URL", "url.form": "form (+ for space)",
      "uni.ph": "Text or \\uXXXX / \\u{…} / &#x…; escapes", "uni.ch": "Char",
      "jwt.parseSec": "Parse & verify", "jwt.ph": "header.payload.signature",
      "jwt.secretPh": "HMAC secret (to verify)", "jwt.secretPh2": "HMAC secret",
      "jwt.header": "Header", "jwt.payload": "Payload", "jwt.signSec": "Sign (HS256 / HS384 / HS512)",
      "jwt.expired": "expired", "jwt.valid": "valid", "jwt.not_yet_valid": "not yet valid",
      "jwt.verifyOk": "Signature valid", "jwt.verifyBad": "Invalid: {0}",
      "cron.hint": "5 fields: min hour day month weekday — or 6 with seconds first",
      "cron.next": "Next runs (local time)", "cron.trunc": "No further runs within the next 4 years",
      "hash.ph": "Text to hash (UTF-8)", "hash.digest": "Digest", "hash.keyPh": "HMAC key (UTF-8)",
      "re.ph": "pattern", "re.subjectPh": "test text", "re.matches": "{0} matches", "re.steps": "{0} steps",
      "re.trunc": "Match limit reached", "re.hl": "Matches", "re.index": "Index", "re.match": "Match",
      "re.groups": "Groups", "re.replace": "Replace", "re.replacePh": "replacement ($1, $<name>, $&)",
      "re.none": "no matches",
      "cr.encrypt": "Encrypt", "cr.decrypt": "Decrypt", "cr.swap": "Swap in/out", "cr.random": "Random",
      "cr.text": "Text", "cr.nopad": "No padding", "cr.input": "Input", "cr.output": "Output",
      "cr.keyPh": "key (UTF-8 text or hex)", "cr.ivPh": "IV / nonce",
      "cr.inPh": "plaintext to encrypt — or ciphertext to decrypt",
      "cr.notUtf8": "Result is not valid UTF-8 — showing hex instead",
      "cr.keyBytes": "key {0} B", "cr.ivBytes": "IV {0} B",
      "cr.needKey": "key must be {0} bytes", "cr.needIv": "IV must be {0} bytes",
      "cr.size": "{0} bytes",
      "cr.gcmHint": "GCM output = ciphertext + 16-byte tag",
    },
    zh: {
      title: "开发者工具箱",
      "tool.ts": "时间戳", "tool.password": "密码", "tool.json": "JSON", "tool.ids": "ID",
      "tool.base64": "Base64", "tool.url": "URL", "tool.unicode": "Unicode", "tool.jwt": "JWT",
      "tool.cron": "Cron", "tool.hash": "哈希", "tool.regex": "正则", "tool.crypto": "加解密",
      now: "现在", convert: "转换", copy: "复制", clear: "清空", generate: "生成", format: "格式化",
      minify: "压缩", encode: "编码", decode: "解码", escape: "转义", unescape: "反转义",
      parse: "解析", verify: "验证", sign: "签名", preview: "预览", compute: "计算",
      copied: "已复制", copyFail: "复制失败，请选中文字后按 ⌘/Ctrl+C",
      "theme.dark": "深色", "theme.light": "浅色",
      "ts.input": "时间戳或日期", "ts.ph": "1700000000 / 1700000000000 / 2026-01-01 00:00:00",
      "ts.local": "本地", "ts.utc": "UTC", "ts.seconds": "秒", "ts.milliseconds": "毫秒",
      "ts.unit": "识别单位：{0}",
      "pw.length": "长度", "pw.count": "数量", "pw.ambiguous": "排除易混淆字符 (Il1O0o)",
      "pw.entropy": "熵约 {0} 位", "pw.entropyEach": "每条约 {0} 位",
      "json.ph": "粘贴 JSON", "json.indent": "缩进", "json.sort": "键排序",
      "json.errPos": "第 {0} 行第 {1} 列：{2}",
      "ids.count": "数量", "ids.size": "NanoID 长度", "ids.machine": "机器号",
      "ids.decodePh": "要解码的 Snowflake ID", "ids.decode": "解码",
      "ids.time": "时间", "ids.sequence": "序列号",
      "b64.ph": "文本或 Base64",
      "url.ph": "文本或百分号编码的 URL", "url.form": "表单（空格为 +）",
      "uni.ph": "文本或 \\uXXXX / \\u{…} / &#x…; 转义", "uni.ch": "字符",
      "jwt.parseSec": "解析与验证", "jwt.ph": "header.payload.signature",
      "jwt.secretPh": "HMAC 密钥（验证用）", "jwt.secretPh2": "HMAC 密钥",
      "jwt.header": "头", "jwt.payload": "载荷", "jwt.signSec": "签名（HS256 / HS384 / HS512）",
      "jwt.expired": "已过期", "jwt.valid": "有效", "jwt.not_yet_valid": "尚未生效",
      "jwt.verifyOk": "签名有效", "jwt.verifyBad": "验证失败：{0}",
      "cron.hint": "5 段：分 时 日 月 周 —— 或 6 段（首段为秒）",
      "cron.next": "接下来执行（本地时间）", "cron.trunc": "未来 4 年内没有更多执行时间",
      "hash.ph": "要哈希的文本（UTF-8）", "hash.digest": "摘要", "hash.keyPh": "HMAC 密钥（UTF-8）",
      "re.ph": "正则表达式", "re.subjectPh": "测试文本", "re.matches": "{0} 个匹配", "re.steps": "{0} 步",
      "re.trunc": "已达匹配上限", "re.hl": "匹配高亮", "re.index": "位置", "re.match": "匹配",
      "re.groups": "分组", "re.replace": "替换", "re.replacePh": "替换串（$1、$<name>、$&）",
      "re.none": "无匹配",
      "cr.encrypt": "加密", "cr.decrypt": "解密", "cr.swap": "交换输入/输出", "cr.random": "随机",
      "cr.text": "文本", "cr.nopad": "无填充", "cr.input": "输入", "cr.output": "输出",
      "cr.keyPh": "密钥（UTF-8 文本或 hex）", "cr.ivPh": "IV / nonce",
      "cr.inPh": "要加密的明文——或要解密的密文",
      "cr.notUtf8": "结果不是有效 UTF-8——已改为 hex 显示",
      "cr.keyBytes": "密钥 {0} 字节", "cr.ivBytes": "IV {0} 字节",
      "cr.needKey": "密钥需 {0} 字节", "cr.needIv": "IV 需 {0} 字节",
      "cr.size": "{0} 字节",
      "cr.gcmHint": "GCM 输出 = 密文 + 16 字节认证标签",
    },
  };
  let lang = /^zh/i.test(navigator.language || "") ? "zh" : "en";
  const t = (key, ...args) => {
    let s = I18N[lang][key] ?? I18N.en[key] ?? key;
    args.forEach((a, i) => { s = s.replace("{" + i + "}", String(a)); });
    return s;
  };

  let toastTimer = 0;
  function toast(msg) {
    const el = $("toast");
    el.textContent = msg;
    el.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { el.hidden = true; }, 1800);
  }

  async function copyText(text, srcEl) {
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      toast(t("copied"));
      return;
    } catch { /* fall through */ }
    try {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand("copy");
      ta.remove();
      if (ok) { toast(t("copied")); return; }
    } catch { /* fall through */ }
    if (srcEl) {
      if (srcEl.select) { srcEl.focus(); srcEl.select(); }
      else {
        const range = document.createRange();
        range.selectNodeContents(srcEl);
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
      }
    }
    toast(t("copyFail"));
  }
  document.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-copy]");
    if (!btn) return;
    const el = $(btn.dataset.copy);
    copyText(el.value !== undefined ? el.value : el.textContent, el);
  });

  const reruns = [];
  const setErr = (id, msg) => { $(id).textContent = msg || ""; };
  const setOut = (id, text) => { $(id).value = text; };

  /* ---------- timestamp ---------- */
  function tsRun() {
    const v = $("tsInput").value.trim();
    setErr("tsErr", "");
    if (!v) {
      $("tsUnit").textContent = "";
      for (const id of ["tsLocal", "tsUtc", "tsIso", "tsSec", "tsMs"]) $(id).textContent = "";
      return;
    }
    try {
      const p = T.ts.parse(v);
      const f = T.ts.formats(p.ms);
      $("tsUnit").textContent = t("ts.unit", p.unit);
      $("tsLocal").textContent = f.local;
      $("tsUtc").textContent = f.utc;
      $("tsIso").textContent = f.iso;
      $("tsSec").textContent = String(f.seconds);
      $("tsMs").textContent = String(f.milliseconds);
    } catch (e) {
      setErr("tsErr", e.message);
    }
  }
  $("tsRun").addEventListener("click", tsRun);
  $("tsNow").addEventListener("click", () => { $("tsInput").value = String(Date.now()); tsRun(); });
  $("tsInput").addEventListener("keydown", (e) => { if (e.key === "Enter") tsRun(); });
  reruns.push(tsRun);

  /* ---------- password ---------- */
  let pwBits = null, pwCount = 1;
  function pwHint() {
    if (pwBits !== null) $("pwEntropy").textContent = t(pwCount > 1 ? "pw.entropyEach" : "pw.entropy", pwBits);
  }
  function pwRun() {
    setErr("pwErr", "");
    const count = Math.max(1, Math.min(100, +$("pwCount").value || 1));
    try {
      const opts = {
        length: +$("pwLen").value,
        lower: $("pwLower").checked,
        upper: $("pwUpper").checked,
        digits: $("pwDigits").checked,
        symbols: $("pwSymbols").checked,
        excludeAmbiguous: $("pwAmb").checked,
      };
      const lines = [];
      for (let i = 0; i < count; i++) {
        const r = T.password.generate(opts);
        lines.push(r.text);
        pwBits = r.entropyBits;
      }
      setOut("pwOut", lines.join("\n"));
      $("pwOut").rows = Math.min(12, Math.max(3, count));
      pwCount = count;
      pwHint();
    } catch (e) {
      setErr("pwErr", e.message);
    }
  }
  $("pwRun").addEventListener("click", pwRun);
  reruns.push(pwHint);

  /* ---------- json ---------- */
  let jsonLastMinify = false;
  function jsonRun(minify) {
    jsonLastMinify = minify;
    setErr("jsonErr", "");
    const v = $("jsonInput").value;
    if (!v.trim()) { setOut("jsonOut", ""); return; }
    const ind = $("jsonIndent").value;
    const r = minify
      ? T.json.minify(v)
      : T.json.format(v, { sortKeys: $("jsonSort").checked, tab: ind === "tab", indent: ind === "tab" ? undefined : +ind });
    if (r.ok) setOut("jsonOut", r.text);
    else {
      setOut("jsonOut", "");
      setErr("jsonErr", r.line !== undefined ? t("json.errPos", r.line, r.column, r.message) : r.message);
    }
  }
  $("jsonFormat").addEventListener("click", () => jsonRun(false));
  $("jsonMinify").addEventListener("click", () => jsonRun(true));
  reruns.push(() => { if ($("jsonInput").value.trim()) jsonRun(jsonLastMinify); });

  /* ---------- ids ---------- */
  function idTypeChanged() {
    const ty = $("idType").value;
    $("idSizeRow").hidden = ty !== "nanoid";
    $("idSfRow").hidden = ty !== "snowflake";
    $("sfDecodeBox").hidden = ty !== "snowflake";
  }
  $("idType").addEventListener("change", idTypeChanged);
  function idRun() {
    const ty = $("idType").value;
    const count = Math.max(1, Math.min(50, +$("idCount").value || 1));
    const lines = [];
    try {
      for (let i = 0; i < count; i++) {
        if (ty === "uuidv4") lines.push(T.ids.uuidv4());
        else if (ty === "uuidv7") lines.push(T.ids.uuidv7());
        else if (ty === "nanoid") lines.push(T.ids.nanoid(+$("idSize").value || 21));
        else if (ty === "snowflake") lines.push(T.ids.snowflake({ machine: +$("idMachine").value || 0, epoch: $("idEpoch").value.trim() || 1288834974657 }));
        else lines.push(T.ids.objectid());
      }
      setOut("idOut", lines.join("\n"));
    } catch (e) {
      setErr("sfErr", e.message);
    }
  }
  $("idRun").addEventListener("click", idRun);
  let sfLast = false;
  function sfDecode() {
    setErr("sfErr", "");
    const v = $("sfInput").value.trim();
    if (!v) { $("sfOut").textContent = ""; sfLast = false; return; }
    try {
      const d = T.ids.snowflakeDecode(v, +$("idEpoch").value || 1288834974657);
      $("sfOut").textContent = `${t("ids.time")}: ${d.time} · ${t("ids.machine")}: ${d.machine} · ${t("ids.sequence")}: ${d.sequence}`;
      sfLast = true;
    } catch (e) {
      setErr("sfErr", e.message);
      $("sfOut").textContent = "";
      sfLast = false;
    }
  }
  $("sfDecode").addEventListener("click", sfDecode);
  $("sfInput").addEventListener("keydown", (e) => { if (e.key === "Enter") sfDecode(); });
  reruns.push(() => { if (sfLast) sfDecode(); });

  /* ---------- base64 ---------- */
  let b64LastDec = false;
  function b64Run(decode) {
    b64LastDec = decode;
    setErr("b64Err", "");
    $("b64Hex").textContent = "";
    const v = $("b64Input").value;
    if (!v) { setOut("b64Out", ""); return; }
    if (!decode) {
      setOut("b64Out", T.base64.encode(v, { urlsafe: $("b64Url").checked, padding: $("b64Pad").checked }));
      return;
    }
    try {
      const r = T.base64.decode(v);
      setOut("b64Out", r.ok ? r.text : "");
      $("b64Hex").textContent = "hex: " + r.hex;
      if (!r.ok) setErr("b64Err", r.reason);
    } catch (e) {
      setOut("b64Out", "");
      setErr("b64Err", e.message);
    }
  }
  $("b64Enc").addEventListener("click", () => b64Run(false));
  $("b64Dec").addEventListener("click", () => b64Run(true));
  reruns.push(() => { if ($("b64Input").value) b64Run(b64LastDec); });

  /* ---------- url ---------- */
  let urlLastDec = false;
  function urlRun(decode) {
    urlLastDec = decode;
    setErr("urlErr", "");
    const v = $("urlInput").value;
    if (!v) { setOut("urlOut", ""); return; }
    const mode = $("urlMode").value;
    if (!decode) setOut("urlOut", T.url.encode(v, mode));
    else {
      const r = T.url.decode(v, mode);
      setOut("urlOut", r.ok ? r.text : "");
      if (!r.ok) setErr("urlErr", r.reason);
    }
  }
  $("urlEnc").addEventListener("click", () => urlRun(false));
  $("urlDec").addEventListener("click", () => urlRun(true));
  reruns.push(() => { if ($("urlInput").value) urlRun(urlLastDec); });

  /* ---------- unicode ---------- */
  let uniLastUnesc = false;
  function uniTable() {
    const plain = uniLastUnesc ? $("uniOut").value : $("uniInput").value;
    const rows = T.unicode.codepoints(plain.slice(0, 200));
    const tbody = $("uniTable").querySelector("tbody");
    tbody.textContent = "";
    for (const r of rows) {
      const tr = document.createElement("tr");
      for (const cell of [r.ch, r.cp, String(r.dec), r.utf8, String(r.utf16)]) {
        const td = document.createElement("td");
        td.textContent = cell;
        tr.appendChild(td);
      }
      tbody.appendChild(tr);
    }
    $("uniTable").hidden = rows.length === 0;
  }
  function uniRun(unescape) {
    uniLastUnesc = unescape;
    setErr("uniErr", "");
    const v = $("uniInput").value;
    if (!v) { setOut("uniOut", ""); $("uniTable").hidden = true; return; }
    try {
      setOut("uniOut", unescape ? T.unicode.unescape(v) : T.unicode.escape(v, $("uniStyle").value));
    } catch (e) {
      setOut("uniOut", "");
      setErr("uniErr", e.message);
    }
    uniTable();
  }
  $("uniEsc").addEventListener("click", () => uniRun(false));
  $("uniUnesc").addEventListener("click", () => uniRun(true));
  reruns.push(() => { if ($("uniInput").value) uniRun(uniLastUnesc); });

  /* ---------- jwt ---------- */
  function jwtParse() {
    setErr("jwtErr", "");
    const v = $("jwtToken").value.trim();
    if (!v) {
      $("jwtAlg").textContent = "";
      $("jwtHeader").textContent = "";
      $("jwtPayload").textContent = "";
      $("jwtTimes").textContent = "";
      return;
    }
    try {
      const p = T.jwt.parse(v);
      $("jwtAlg").textContent = "alg: " + p.alg;
      $("jwtHeader").textContent = JSON.stringify(p.header, null, 2);
      $("jwtPayload").textContent = JSON.stringify(p.payload, null, 2);
      const box = $("jwtTimes");
      box.textContent = "";
      for (const c of p.times) {
        const row = document.createElement("div");
        row.className = "kv";
        const k = document.createElement("span");
        k.textContent = c.claim;
        const val = document.createElement("code");
        val.textContent = c.iso;
        const st = document.createElement("span");
        if (c.status) {
          st.className = c.status === "valid" ? "ok" : "bad";
          st.textContent = t("jwt." + c.status.replace(/ /g, "_"));
        }
        row.append(k, val, st);
        box.appendChild(row);
      }
    } catch (e) {
      setErr("jwtErr", e.message);
      $("jwtAlg").textContent = "";
      $("jwtHeader").textContent = "";
      $("jwtPayload").textContent = "";
      $("jwtTimes").textContent = "";
    }
  }
  let jwtVerified = false;
  function jwtVerify() {
    const v = $("jwtToken").value.trim();
    if (!v) { $("jwtVerifyOut").textContent = ""; jwtVerified = false; return; }
    const r = T.jwt.verify(v, $("jwtSecret").value);
    const el = $("jwtVerifyOut");
    el.className = "hint " + (r.ok ? "ok" : "bad");
    el.textContent = r.ok ? t("jwt.verifyOk") : t("jwt.verifyBad", r.reason);
    jwtVerified = true;
  }
  function jwtSign() {
    setErr("jwtSignErr", "");
    try {
      setOut("jwtSignOut", T.jwt.sign($("jwtPayloadIn").value, $("jwtSignSecret").value, $("jwtSignAlg").value));
    } catch (e) {
      setOut("jwtSignOut", "");
      setErr("jwtSignErr", e.message);
    }
  }
  $("jwtParse").addEventListener("click", jwtParse);
  $("jwtVerify").addEventListener("click", jwtVerify);
  $("jwtSign").addEventListener("click", jwtSign);
  reruns.push(() => {
    if ($("jwtToken").value.trim()) { jwtParse(); if (jwtVerified) jwtVerify(); }
    if ($("jwtSignOut").value) jwtSign();
  });

  /* ---------- cron ---------- */
  function cronRun() {
    setErr("cronErr", "");
    $("cronTrunc").hidden = true;
    const v = $("cronInput").value.trim();
    const list = $("cronRuns");
    list.textContent = "";
    if (!v) { $("cronDesc").textContent = ""; return; }
    try {
      $("cronDesc").textContent = T.cron.describe(v, lang === "zh" ? "zh" : "en");
      const r = T.cron.next(v, Date.now(), 5);
      for (const d of r.runs) {
        const li = document.createElement("li");
        li.textContent = `${T.ts.fmt(d, false)}  (${d.toISOString()})`;
        list.appendChild(li);
      }
      $("cronTrunc").hidden = !r.truncated;
    } catch (e) {
      $("cronDesc").textContent = "";
      setErr("cronErr", e.message);
    }
  }
  $("cronRun").addEventListener("click", cronRun);
  $("cronInput").addEventListener("keydown", (e) => { if (e.key === "Enter") cronRun(); });
  reruns.push(cronRun);

  /* ---------- hash ---------- */
  $("hashMode").addEventListener("change", () => { $("hashKeyRow").hidden = $("hashMode").value !== "hmac"; });
  function hashRun() {
    setErr("hashErr", "");
    const v = $("hashInput").value;
    if (!v) { setOut("hashOut", ""); return; }
    try {
      const alg = $("hashAlg").value;
      const bytes = $("hashMode").value === "hmac"
        ? T.hash.hmac(alg, T.util.bytesOf($("hashKey").value), T.util.bytesOf(v))
        : T.hash.digest(alg, T.util.bytesOf(v));
      setOut("hashOut", T.util.hexOf(bytes));
    } catch (e) {
      setOut("hashOut", "");
      setErr("hashErr", e.message);
    }
  }
  $("hashRun").addEventListener("click", hashRun);
  reruns.push(() => { if ($("hashOut").value) hashRun(); });

  /* ---------- regex ---------- */
  function reFlags() {
    return ["reG", "reI", "reM", "reS", "reU", "reY"].filter((id) => $(id).checked).map((id) => id[2].toLowerCase()).join("");
  }
  function reRun() {
    setErr("reErr", "");
    const pattern = $("rePattern").value;
    const flags = reFlags();
    const subject = $("reSubject").value;
    const hl = $("reHl");
    const tbody = $("reTable").querySelector("tbody");
    hl.textContent = "";
    tbody.textContent = "";
    $("reTable").hidden = true;
    $("reTrunc").hidden = true;
    if (!pattern) { $("reStats").textContent = ""; setOut("reReplOut", ""); return; }
    const r = T.regex.test(pattern, flags, subject);
    if (!r.ok) {
      $("reStats").textContent = "";
      setErr("reErr", r.reason);
      setOut("reReplOut", "");
      return;
    }
    $("reStats").textContent = r.matches.length ? t("re.matches", r.matches.length) + " · " + t("re.steps", r.steps) : t("re.none");
    $("reTrunc").hidden = !r.truncated;
    let at = 0;
    r.matches.slice(0, 500).forEach((m, i) => {
      hl.appendChild(document.createTextNode(subject.slice(at, m.index)));
      const mark = document.createElement("mark");
      mark.textContent = m.text;
      mark.title = "#" + (i + 1) + " @" + m.index;
      hl.appendChild(mark);
      at = m.end;
    });
    hl.appendChild(document.createTextNode(subject.slice(at)));
    for (const [i, m] of r.matches.slice(0, 200).entries()) {
      const tr = document.createElement("tr");
      const groups = m.groups.map((g, k) => (g.name || k + 1) + ": " + (g.text === undefined ? "—" : JSON.stringify(g.text))).join("  ");
      for (const cell of [String(i + 1), m.index + "–" + m.end, JSON.stringify(m.text), groups || "—"]) {
        const td = document.createElement("td");
        td.textContent = cell;
        tr.appendChild(td);
      }
      tbody.appendChild(tr);
    }
    $("reTable").hidden = r.matches.length === 0;
    const rr = T.regex.replace(pattern, flags, subject, $("reRepl").value);
    setOut("reReplOut", rr.ok ? rr.text : "");
    if (!rr.ok) setErr("reErr", rr.reason);
  }
  let reTimer = 0;
  const reSoon = () => { clearTimeout(reTimer); reTimer = setTimeout(reRun, 150); };
  for (const id of ["rePattern", "reSubject", "reRepl", "reG", "reI", "reM", "reS", "reU", "reY"]) $(id).addEventListener("input", reSoon);
  $("rePattern").addEventListener("keydown", (e) => { if (e.key === "Enter") reRun(); });
  reruns.push(reRun);

  /* ---------- crypto ---------- */
  const crFatal = new TextDecoder("utf-8", { fatal: true });
  let crLastDir = "";
  const crSpec = () => T.crypto.spec($("crAlg").value);
  function crBytes(text, fmt) {
    if (fmt === "hex") return T.util.fromHex(text);
    if (fmt === "base64") return T.base64.decodeBytes(text);
    return T.util.bytesOf(text);
  }
  function crText(bytes, fmt) {
    if (fmt === "hex") return T.util.hexOf(bytes);
    if (fmt === "base64") return T.base64.encodeBytes(bytes, false, true);
    return crFatal.decode(bytes);
  }
  function crKeyLen() { try { return crBytes($("crKey").value, $("crKeyFmt").value).length; } catch { return null; } }
  function crIvLen() { try { return crBytes($("crIv").value, $("crIvFmt").value).length; } catch { return null; } }
  function crInfo() {
    const alg = $("crAlg").value, spec = crSpec(), mode = $("crMode").value, parts = [];
    const keyLen = crKeyLen();
    if (spec.stream) {
      parts.push(alg.toUpperCase(), keyLen === null ? t("cr.needKey", "1–256") : t("cr.keyBytes", keyLen));
    } else {
      let name = alg.toUpperCase();
      if (alg === "aes" && spec.keys.includes(keyLen)) name += "-" + keyLen * 8;
      parts.push(name + " · " + mode.toUpperCase());
      if (spec.pad && mode !== "ctr" && mode !== "gcm") parts.push($("crPad").value === "none" ? t("cr.nopad") : $("crPad").value.toUpperCase());
    }
    if (spec.keys) parts.push(keyLen === null ? t("cr.needKey", spec.keys.join("/")) : t("cr.keyBytes", keyLen));
    if (spec.iv && spec.iv[mode]) {
      const n = crIvLen();
      parts.push(n === null ? t("cr.needIv", spec.iv[mode]) : t("cr.ivBytes", n));
    }
    if (mode === "gcm") parts.push(t("cr.gcmHint"));
    $("crInfo").textContent = parts.join(" · ");
  }
  function crSync() {
    const alg = $("crAlg").value, spec = crSpec();
    const modeSel = $("crMode"), prevMode = modeSel.value;
    modeSel.textContent = "";
    for (const m of spec.modes) {
      const o = document.createElement("option");
      o.value = m;
      o.textContent = m.toUpperCase();
      modeSel.appendChild(o);
    }
    if (spec.modes.includes(prevMode)) modeSel.value = prevMode;
    const mode = modeSel.value;
    modeSel.hidden = !spec.modes.length;
    $("crPad").hidden = !spec.pad || mode === "ctr" || mode === "gcm";
    $("crKeyGen").hidden = !spec.keys;
    const sizeSel = $("crKeySize"), prevSize = Number(sizeSel.value);
    sizeSel.textContent = "";
    if (spec.keys && spec.keys.length > 1) {
      for (const n of spec.keys) {
        const o = document.createElement("option");
        o.value = String(n);
        o.textContent = alg === "aes" ? n * 8 + " bit" : t("cr.size", n);
        sizeSel.appendChild(o);
      }
      sizeSel.value = String(spec.keys.includes(prevSize) ? prevSize : spec.keys[spec.keys.length - 1]);
    }
    sizeSel.hidden = !(spec.keys && spec.keys.length > 1);
    $("crIvRow").hidden = !(spec.iv && spec.iv[mode]);
    crInfo();
  }
  function crRun(dir) {
    setErr("crErr", "");
    crLastDir = dir;
    const raw = $("crInput").value;
    if (!raw) { setOut("crOut", ""); crInfo(); return; }
    let out;
    try {
      out = T.crypto.crypt({
        dir,
        alg: $("crAlg").value,
        mode: $("crMode").value,
        key: crBytes($("crKey").value, $("crKeyFmt").value),
        iv: $("crIvRow").hidden ? null : crBytes($("crIv").value, $("crIvFmt").value),
        data: crBytes(raw, $("crInFmt").value),
        padding: $("crPad").value,
      });
    } catch (e) {
      setOut("crOut", "");
      setErr("crErr", String(e.message || e));
      crInfo();
      return;
    }
    try {
      setOut("crOut", crText(out, $("crOutFmt").value));
    } catch {
      $("crOutFmt").value = "hex";
      setOut("crOut", T.util.hexOf(out));
      setErr("crErr", t("cr.notUtf8"));
    }
    crInfo();
  }
  $("crAlg").addEventListener("change", () => {
    if ($("crOutFmt").value === "text") $("crOutFmt").value = "base64";
    crSync();
  });
  for (const id of ["crMode", "crPad", "crKeySize"]) $(id).addEventListener("change", crSync);
  for (const id of ["crKey", "crIv", "crKeyFmt", "crIvFmt"]) $(id).addEventListener("input", crInfo);
  $("crKeyGen").addEventListener("click", () => {
    $("crKeyFmt").value = "hex";
    $("crKey").value = T.util.hexOf(T.crypto.randomKey($("crAlg").value, $("crKeySize").hidden ? undefined : Number($("crKeySize").value)));
    crInfo();
  });
  $("crIvGen").addEventListener("click", () => {
    $("crIvFmt").value = "hex";
    $("crIv").value = T.util.hexOf(T.crypto.randomIv($("crAlg").value, $("crMode").value));
    crInfo();
  });
  $("crEnc").addEventListener("click", () => crRun("encrypt"));
  $("crDec").addEventListener("click", () => crRun("decrypt"));
  $("crSwap").addEventListener("click", () => {
    const out = $("crOut").value;
    if (!out) return;
    const inFmt = $("crInFmt").value;
    $("crInFmt").value = $("crOutFmt").value;
    $("crOutFmt").value = inFmt;
    $("crInput").value = out;
    setOut("crOut", "");
    setErr("crErr", "");
    crInfo();
  });
  $("crInput").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) crRun(crLastDir || "encrypt");
  });
  crSync();
  reruns.push(() => { crSync(); if (crLastDir && $("crOut").value) crRun(crLastDir); });

  /* ---------- shell: nav, language, theme ---------- */
  const navBtns = [...document.querySelectorAll("#nav button")];
  function show(tool) {
    for (const b of navBtns) b.classList.toggle("active", b.dataset.tool === tool);
    for (const p of document.querySelectorAll(".panel")) p.hidden = p.id !== "panel-" + tool;
  }
  for (const b of navBtns) b.addEventListener("click", () => show(b.dataset.tool));
  show("ts");

  const inIde = !!window.openidea;
  if (inIde) $("themeBtn").hidden = true;
  else {
    const themeLabel = () => {
      $("themeBtn").textContent = document.documentElement.dataset.theme === "dark" ? t("theme.light") : t("theme.dark");
    };
    $("themeBtn").addEventListener("click", () => {
      const root = document.documentElement;
      root.dataset.theme = root.dataset.theme === "dark" ? "light" : "dark";
      themeLabel();
    });
    themeLabel();
  }

  function applyStatic() {
    document.documentElement.lang = lang === "zh" ? "zh-CN" : "en";
    for (const el of document.querySelectorAll("[data-i18n]")) el.textContent = t(el.dataset.i18n);
    for (const el of document.querySelectorAll("[data-i18n-ph]")) el.placeholder = t(el.dataset.i18nPh);
    $("langBtn").textContent = lang === "zh" ? "EN" : "中文";
    if (!inIde) $("themeBtn").textContent = document.documentElement.dataset.theme === "dark" ? t("theme.light") : t("theme.dark");
    for (const fn of reruns) { try { fn(); } catch { /* keep the rest of the UI alive */ } }
  }
  $("langBtn").addEventListener("click", () => { lang = lang === "zh" ? "en" : "zh"; applyStatic(); });
  applyStatic();
  idTypeChanged();

  /* ---------- clear: restore a panel to its initial state ---------- */
  const clearHooks = {
    password: () => { pwBits = null; pwCount = 1; $("pwOut").rows = 3; },
    json: () => { jsonLastMinify = false; },
    ids: () => { sfLast = false; idTypeChanged(); },
    base64: () => { b64LastDec = false; },
    url: () => { urlLastDec = false; },
    unicode: () => { uniLastUnesc = false; },
    jwt: () => { jwtVerified = false; $("jwtVerifyOut").className = "hint"; },
    hash: () => { $("hashKeyRow").hidden = $("hashMode").value !== "hmac"; },
    regex: () => { clearTimeout(reTimer); $("reTable").hidden = true; $("reTrunc").hidden = true; },
    crypto: () => { crLastDir = ""; crSync(); },
  };
  const clearHidden = [...document.querySelectorAll(".panel")].map((p) => [p, [...p.querySelectorAll("[hidden]")]]);
  document.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-clear]");
    if (!btn) return;
    const panel = btn.closest(".panel");
    for (const el of panel.querySelectorAll("input, textarea, select")) {
      if (el.type === "checkbox") el.checked = el.defaultChecked;
      else if (el.tagName === "SELECT") {
        const i = [...el.options].findIndex((o) => o.defaultSelected);
        el.selectedIndex = i < 0 ? 0 : i;
      } else el.value = el.defaultValue;
    }
    for (const el of panel.querySelectorAll(".error, .hint, .re-hl, code, pre, ol, tbody, #jwtTimes")) {
      if (!el.hasAttribute("data-i18n")) el.textContent = "";
    }
    for (const [p, els] of clearHidden) if (p === panel) for (const el of els) el.hidden = true;
    const hook = clearHooks[panel.id.replace("panel-", "")];
    if (hook) hook();
  });
})();