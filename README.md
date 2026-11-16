# Developer Toolbox / 开发者工具箱

An OpenIDEA plugin: eleven everyday developer tools in one right-side tool window.
OpenIDEA 插件：右侧工具窗里的十一个日常开发小工具。

**Open / 打开**: right toolbar → *Developer Toolbox* / 右侧工具栏 → *开发者工具箱*。

## Tools / 工具

| Tool | 工具 | What it does |
| --- | --- | --- |
| Timestamp | 时间戳转换 | epoch s/ms/µs/ns ↔ date, local + UTC + ISO formats |
| Password | 密码生成器 | CSPRNG passwords, charset options, entropy estimate |
| JSON | JSON 格式化 | format / minify / validate with error line-column, key sorting |
| IDs | ID 生成器 | UUID v4/v7, NanoID, Snowflake, MongoDB-style ObjectId, batches |
| Base64 | Base64 | UTF-8 safe encode/decode, standard + URL-safe alphabet |
| URL | URL 编解码 | component / full-URI / form (`+`) modes |
| Unicode | Unicode 编解码 | `\uXXXX`, `\u{…}`, HTML entities, codepoint table |
| JWT | JWT 解析/生成 | parse claims with expiry status; sign & verify HS256/384/512 |
| Cron | Cron 表达式 | 5/6-field parse, next run times, plain-language description |
| Regex | 正则测试 | live match highlighting, group table, replace; budgeted local matcher (no catastrophic hangs) |
| Hash | 哈希 | MD5, SHA-1, SHA-256, SHA-384, SHA-512 (text or hex input) |

## Privacy / 隐私

The UI is a packaged web view (`web/index.html`) loaded in the IDE's sandboxed
frame: opaque origin, **no network access**, no cookies or storage. All
computation happens in the page's own JavaScript; randomness comes from
`crypto.getRandomValues`; JWT signing uses a local HMAC-SHA2 implementation.
Regex matching runs on a step-budgeted backtracking VM (the sandbox CSP blocks
Workers), so a catastrophic pattern reports an error instead of freezing the IDE.
The only capability requested is `clipboard` (copy buttons).

界面是包内 web 视图（`web/index.html`），运行在 IDE 沙箱框架中： opaque origin、
**禁止网络**、无 cookie 与存储。全部计算在页面自有 JavaScript 内完成；随机数来自
`crypto.getRandomValues`；JWT 签名使用本地 HMAC-SHA2 实现。唯一申请的能力是
`clipboard`（复制按钮）。

No WebAssembly component is needed: the manifest declares a `web` view only.
无需 WebAssembly 组件：manifest 仅声明 `web` 视图。

## Build & pack / 构建与打包

```sh
openidea-plugin check .
openidea-plugin pack . --key <publisher.key> --publisher alivop --out alivop.devtoolbox-0.1.0.oiplugin
node tests/tools.test.mjs   # logic unit tests / 逻辑单元测试
```

## License / 许可

Apache-2.0 — see [LICENSE](LICENSE).