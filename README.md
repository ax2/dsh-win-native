# dsh-win-native

**Windows 正确性层：把 agent 平时用 PowerShell 文本解析凑合的那些判断，做成有回执、有边界、说实话的工具。**

[English](#english) · MIT · `dsh-win-native` · 6 个工具 · 无安装期脚本

---

## 这个插件解决什么问题

Windows 上的 agent 每天在做同一类事：猜一个字节流是什么编码、判断一个路径为什么会失败、把 `netstat` 的输出用正则抠出来、统计一个目录多大、找重复文件。这些事用临时 PowerShell 拼出来通常有三个毛病：

1. **猜。** 编码靠"看起来像 GBK"，路径靠"报错了就加双反斜杠"，端口占用靠"LISTENING 应该就是活着"。猜错时 agent 不会说"我不确定"。
2. **不说边界。** 目录统计跑了一半被截断、重复文件只哈希了一部分，结果看起来和完整结果一模一样。
3. **不守恒。** 一次转换悄悄把 4 个汉字变成 `?`，没有任何地方记录这件事。

`dsh-win-native` 把这六件事做成六个工具，每个都遵守 DSH 插件契约：返回 `{ result, meta }` 回执、结构化输入超预算**拒绝**而不是截断、不支持的取值连允许列表一起报出、领域失败作为**成功结果**返回（`ENOENT` 是数据，不是崩溃）。

## 只读承诺（重要）

| 工具 | 会不会碰文件系统 | 会不会写 |
|---|---|---|
| `encoding_detect` | 不会。只分析你给的 base64 字节 | 不会 |
| `encoding_convert` | 不会。只转换你给的 base64 字节 | 不会 |
| `path_inspect` | **不会**。纯字符串分析，路径不存在也能分析 | 不会 |
| `netstat_parse` | 不会。只解析你粘贴的文本 | 不会 |
| `dir_usage` | **会读**。`lstat` + `opendir` 遍历你指定的绝对路径 | **不会** |
| `file_duplicates` | **会读**。读取文件内容做流式 SHA-256 | **不会** |

**这个插件永远不会删除、移动、重命名或写入任何文件**——包括它自己找到的重复文件。`file_duplicates` 只**报告**哪些文件重复、能回收多少字节，回收动作永远由人或上层策略决定。两个遍历工具用 `lstat` 而不是 `stat`，所以符号链接、junction 和其他 reparse point 一律**跳过并上报**（`skipped_links`），绝不跟随——跟随一个 junction 可能走出你要求的目录树，在 Windows 上还可能成环。

两个会读文件的工具**拒绝相对路径**。相对路径的含义取决于宿主进程是怎么启动的，正是这个插件要消灭的那类不确定性；所以拒绝比"帮你解析"更诚实。

## 六个工具

### 1. `encoding_detect` — 这是什么编码？

按 **BOM → 严格 UTF-8 → 打分候选** 的顺序判断，返回最佳候选、`high`/`medium`/`low` 置信度，以及**所有得分接近的候选**。它不会在不确定时假装确定。

```jsonc
// 输入：GBK 字节的 base64（"配置文件路径：C:\Users\ax2，服务未启动。"）
{ "base64": "..." }
```

```jsonc
{
  "result": {
    "encoding": "gb18030",
    "confidence": "high",
    "bom": "none",
    "byte_length": 40,
    "alternatives": [
      { "encoding": "gb18030", "score": 1,    "replacements": 0, "suspicious": 0, "round_trip": true,  "sample": "配置文件路径：C:\\Users\\ax2，服务未启动。" },
      { "encoding": "latin1",  "score": 0.75, "replacements": 0, "suspicious": 0, "round_trip": true,  "sample": "ÅäÖÃÎÄ¼þÂ·¾¶£ºC:\\Users\\ax2£¬·þÎñÎ´Æô¶¯¡£" },
      { "encoding": "big5",    "score": 0.743,"replacements": 0, "suspicious": 2, "round_trip": true,  "sample": "饜离恅璃繚噤ㄩC:\\Users\\ax2ㄛ督昢帤ぎ雄﹝" },
      { "encoding": "utf-8",   "score": 0.15, "replacements": 22,"suspicious": 0, "round_trip": false, "sample": "�����ļ�·����C:\\Users\\ax2������δ������" }
    ],
    "signals": ["scored:gb18030=1,latin1=0.75,big5=0.743,utf-8=0.15,shift_jis=0"]
  },
  "meta": { "bytesIn": 56, "bytesOut": 1128, "truncated": false, "notes": [] }
}
```

**短样本会诚实地报 `low`。** 两个汉字（4 字节）在 GB18030 和 Big5 里都能合法解码，得分完全相同：

```jsonc
// 输入：GBK 字节的 base64（"中文"）
{
  "result": {
    "encoding": "gb18030",
    "confidence": "low",
    "alternatives": [
      { "encoding": "gb18030", "score": 1, "sample": "中文" },
      { "encoding": "big5",    "score": 1, "sample": "笢恅" },
      { "encoding": "latin1",  "score": 0.75, "sample": "ÖÐÎÄ" },
      { "encoding": "shift_jis","score": 0.65,"sample": "ﾖﾐﾎﾄ" }
    ],
    "signals": ["scored:gb18030=1,big5=1,latin1=0.75,shift_jis=0.65,utf-8=0.15", "ambiguous-candidates-within-score-margin"]
  },
  "meta": {
    "notes": ["confidence is low: at least two code pages explain these bytes equally well. Pass an explicit `from` to encoding_convert, or confirm with a larger sample, before trusting the text."]
  }
}
```

> **这是设计的一部分，不是缺陷。** 在 iconv-lite 的码表下，**每一个**合法的 Big5 双字节对同时也是合法的 GB18030 双字节对（实测交集 16777 对，零分歧）；Shift-JIS 与 GB18030 也是同样情况（7326 对，零分歧）。所以短中日文样本的歧义是**信息论层面**的：不存在能区分它们的字节级证据。工具的职责是把这个事实**报出来**，而不是掷骰子——`gb18030` 之所以排在前面，是因为一个显式的、写在 TSDoc 里的码页先验（`gb18030` 的加分随"低位引导字节占比"衰减，`shift_jis` 固定小额加分）。`score` 字段是**原始证据**，先验只影响排序，绝不改变打印出来的分数。

### 2. `encoding_convert` — 转换，并且报告丢了多少

支持 `utf-8`、`utf-16le`、`utf-16be`、`gbk`、`gb18030`、`big5`、`shift_jis`、`latin1`、`ascii`，`from: "auto"` 先检测。有损转换**一定被报出来**，绝不静默：

```jsonc
// 输入："中文测试" 的 UTF-8 字节 → latin1
{ "base64": "5Lit5paH5rWL6K+V", "from": "utf-8", "to": "latin1", "bom": "strip" }
```

```jsonc
{
  "result": {
    "base64": "Pz8/Pw==",
    "source_encoding": "utf-8",
    "target_encoding": "latin1",
    "source_bom": "none",
    "output_bom": "none",
    "bytes_in": 12,
    "bytes_out": 4,
    "lossy_characters": 4,
    "lossy_list": [
      { "code_point": "U+4E2D", "char": "中", "count": 1 },
      { "code_point": "U+6587", "char": "文", "count": 1 },
      { "code_point": "U+6D4B", "char": "测", "count": 1 },
      { "code_point": "U+8BD5", "char": "试", "count": 1 }
    ],
    "hex_preview": "3f 3f 3f 3f",
    "text": "中文测试",
    "changed": true,
    "signals": ["source-declared:utf-8", "lossy:4-characters-replaced", "bom:stripped"]
  },
  "meta": {
    "bytesIn": 16,
    "bytesOut": 512,
    "truncated": false,
    "notes": ["LOSSY: 4 character(s) have no representation in latin1 and were replaced; first offenders: \"中\" (U+4E2D), \"文\" (U+6587), \"测\" (U+6D4B), \"试\" (U+8BD5). The output is not a faithful round trip."]
  }
}
```

有 BOM 的源文件会被正确识别并剥离，`text` 里**不会**留下 U+FEFF：

```jsonc
// 输入：UTF-8 BOM + "中文测试"
{ "base64": "77u/5Lit5paH5rWL6K+V", "to": "gbk", "bom": "strip" }
// result: { "source_bom": "utf-8", "output_bom": "none", "bytes_out": 8,
//           "hex_preview": "d6 d0 ce c4 b2 e2 ca d4", "text": "中文测试",
//           "lossy_characters": 0, "signals": ["auto-detected-source:utf-8:high", "lossless-round-trip", "bom:stripped"] }
```

### 3. `path_inspect` — 这条路径会怎么炸？

纯字符串分析，**不碰文件系统**，所以对不存在的路径同样有效。逐条检查：绝对/相对、`\\?\` 扩展前缀、UNC vs 盘符 vs 根相对 vs 盘符相对（`C:foo`）、保留设备名（`CON`、`PRN`、`AUX`、`NUL`、`COM1-9`、`LPT1-9`，**带扩展名也算**，如 `CON.txt`）、非法字符、控制字符、结尾空格或点、8.3 安全名、单段长度、以及总长度对 260 的 MAX_PATH 判定。

```jsonc
// 输入：{ "path": "C:\\temp\\CON.txt" }
{
  "result": {
    "input": "C:\\temp\\CON.txt",
    "absolute": true,
    "extended": false,
    "kind": "drive",
    "drive": "C",
    "canonical": "C:\\temp\\CON.txt",
    "length": 15,
    "canonical_length": 15,
    "max_path_limit": 260,
    "safe_for_max_path": false,
    "requires_extended_prefix": false,
    "segments": [
      { "value": "temp",    "index": 0, "safe_8_3": true,  "length": 4 },
      { "value": "CON.txt", "index": 1, "safe_8_3": false, "length": 7 }
    ],
    "issues": [
      { "code": "reserved_name", "severity": "error",
        "detail": "segment \"CON.txt\" is a reserved DOS device name, even with an extension or a path prefix",
        "position": 8 }
    ]
  },
  "meta": { "bytesIn": 15, "bytesOut": 530, "truncated": false, "notes": [] }
}
```

盘符相对路径会被正确拆段——盘符是根，不是第一段：

```jsonc
// 输入：{ "path": "C:foo\\bar" }
// result.kind        = "drive"
// result.absolute    = false
// result.canonical   = "C:foo\\bar"
// result.segments    = [{ "value": "foo", "index": 0, ... }, { "value": "bar", "index": 1, ... }]
// result.issues      = [{ "code": "drive_relative", "severity": "error",
//                         "detail": "\"C:\" is drive-relative: it resolves against the current directory of that drive, which differs per process",
//                         "position": 2 }]
// meta.notes         = ["the path is not absolute; it would be resolved against the caller working directory"]
```

超长路径会给出确定的结论和可执行的建议：

```jsonc
// 输入：{"path": "C:\\data\\segment\\...\\file.txt"}（336 字符）
// result.requires_extended_prefix = true
// result.safe_for_max_path        = false
// result.issues = [{ "code": "above_max_path", "severity": "warning",
//                    "detail": "the path is 336 characters; without \\\\?\\ or the LongPathsEnabled policy, Win32 APIs fail at 259 characters" }]
// meta.notes    = ["use the canonical form (or the LongPathsEnabled policy) or Win32 APIs will fail on this path"]
```

UNC 路径的 canonical 形式保持 `\\` 开头（不会被规范化成单反斜杠）：

```jsonc
// 输入：{ "path": "\\\\server\\share\\dir\\file.txt" }
// result.kind = "unc", result.drive = null
// result.canonical = "\\\\server\\share\\dir\\file.txt", result.canonical_length = 27
// result.segments = [{ "value": "dir", "index": 1 }, { "value": "file.txt", "index": 2 }]   // server/share 属于根
// result.issues = []
```

每个 issue 都带 `code`、`severity` 和 `position`（在**原始字符串**里的下标），所以 agent 可以精确定位到出问题的那一段，而不是重读整条路径。

### 4. `netstat_parse` — 端口到底谁在听？

解析粘贴的 `netstat -ano` / `netstat -anob` 或 PowerShell `Get-NetTCPConnection` 表格，自动识别方言。返回监听端点（带 PID 和**文本里真有的话**进程名）、按远端端点聚合的已建立连接、重复绑定（同一端口同时绑在 `0.0.0.0` 和具体地址上）、以及按状态和协议的计数。

```jsonc
{
  "dialect": "netstat",
  "summary": { "tcp_rows": 5, "udp_rows": 1, "listening_tcp": 3, "listening_udp": 1,
               "established": 2, "distinct_pids": 4, "ports": 5 },
  "listening": [
    { "protocol": "tcp", "address": "0.0.0.0",   "port": 135, "state": "LISTENING", "pid": 1012, "process_name": null },
    { "protocol": "tcp", "address": "0.0.0.0",   "port": 445, "state": "LISTENING", "pid": 4,    "process_name": null },
    { "protocol": "tcp", "address": "127.0.0.1", "port": 445, "state": "LISTENING", "pid": 4,    "process_name": null },
    { "protocol": "udp", "address": "0.0.0.0",   "port": 3702, "state": "UDP",      "pid": 3140, "process_name": null }
  ],
  "duplicate_binds": [
    { "protocol": "tcp", "port": 445, "wildcard_conflict": true, "multi_pid": false,
      "bindings": [{ "address": "0.0.0.0", "pid": 4 }, { "address": "127.0.0.1", "pid": 4 }] }
  ],
  "limitations": [
    "whether a listening PID still exists cannot be determined from netstat text; resolve the pid separately",
    "process names are only present with `netstat -b` (often \"Access denied\") or from Get-NetTCPConnection -OwningProcess",
    "UDP has no connection state, so a UDP row without a foreign address is reported as a bind rather than a session"
  ],
  "notes": []
}
```

**它绝不编造文本里没有的事实。** 监听 PID 是否还活着、UDP"连接"的状态、没带 `-b` 时的进程名——这三件事这段文本里根本没有，所以它们出现在 `limitations` 里，而不是被猜出来。无法识别的行被跳过并**计数上报**（`notes`），不会被硬塞进某个字段。

### 5. `dir_usage` — 这个目录多大？（只读）

`lstat` + `opendir` 流式遍历，返回总字节、文件/目录数、最大的若干文件、扩展名直方图。受 `max_files`（默认 20000）、`max_depth`（默认 8）、`max_bytes`（默认 512 MiB）约束；**撞到任何一个预算都会把 `truncated` 置真并说明是哪一个**。

```jsonc
// 输入：{ "path": "C:\\Users\\ax2\\AppData\\Local\\Temp\\demo", "top_n": 2 }
{
  "result": {
    "root": "C:\\Users\\ax2\\AppData\\Local\\Temp\\demo",
    "total_bytes": 5632,
    "files": 4,
    "directories": 2,
    "largest": [
      { "path": "...\\app.log",    "size": 4096, "depth": 1 },
      { "path": "...\\logs\\old.log", "size": 1024, "depth": 2 }
    ],
    "extensions": [ { "extension": ".log", "files": 2, "bytes": 5120 },
                    { "extension": ".ini", "files": 1, "bytes": 512 },
                    { "extension": ".txt", "files": 1, "bytes": 16 } ],
    "skipped_links": [],
    "unreadable": [],
    "truncated": false,
    "notes": []
  },
  "meta": { "bytesIn": 45, "bytesOut": 521, "truncated": false, "notes": [] }
}
```

预算生效时的样子——`truncated` 为真，且 note 说清是哪个预算：

```jsonc
// 输入：{ "path": "<上面的目录>", "max_files": 3 }
// result.files = 3, result.truncated = true
// meta.truncated = true
// meta.notes = ["file budget maxFiles=3 reached; the totals are a lower bound"]
```

根目录打不开时**不抛异常**——`ENOENT` 是数据：

```jsonc
// 输入：一个不存在的绝对路径
// result.files = 0
// result.unreadable = [{ "path": "...", "code": "ENOENT", "message": "..." }]
// meta.truncated = true
// meta.notes = ["the root directory itself could not be opened; the totals describe nothing"]
```

### 6. `file_duplicates` — 哪些文件是重复的？（只读）

先按**大小**分组，只对同尺寸候选做**流式 SHA-256**。返回重复组（含哈希、尺寸、数量、可回收字节、全部路径）、`reclaimable_bytes`、以及完整的守恒计数。

```jsonc
// 输入：{ "path": "C:\\temp\\demo" }
{
  "result": {
    "root": "C:\\temp\\demo",
    "groups": [
      { "hash": "…64 hex…", "size": 16, "count": 2, "reclaimable": 16,
        "paths": ["C:\\temp\\demo\\copy-a.txt", "C:\\temp\\demo\\copy-b.txt"] }
    ],
    "groups_total": 1,
    "reclaimable_bytes": 16,
    "files_seen": 5,
    "candidates_hashed": 2,
    "files_hashed": 2,
    "bytes_hashed": 32,
    "unreadable": [],
    "truncated": false,
    "notes": ["3 file(s) had a unique size and needed no hashing"]
  },
  "meta": { "bytesIn": 45, "bytesOut": 536, "truncated": false, "notes": ["3 file(s) had a unique size and needed no hashing"] }
}
```

**哈希预算用完时，剩余候选被报为"未哈希"，绝不被当成"不重复"：**

```jsonc
// 输入：{ "path": "...", "max_bytes_hashed": 50 }（两个 100 字节的同内容文件）
// result.groups_total = 0, result.files_hashed = 0, result.truncated = true
// meta.notes = ["byte budget maxBytesHashed=50 reached; files that were not hashed may or may not be duplicates"]
```

同尺寸但内容不同的文件**一定不会被合并**；无法读取的路径带 `stage`（`list` / `stat` / `read`）和错误码出现在 `unreadable` 里。空文件被排除并附上说明——它技术上"重复"，但回收它没有任何意义。

## 预算与配置

所有预算都能在插件配置里覆盖（宿主会用 schemastery 校验），非法值（非正数、`NaN`、非整数）回落到默认值：

| 配置项 | 默认值 | 管什么 |
|---|---|---|
| `maxInputBytes` | 262144（256 KiB） | 结构化输入的**硬**上限；超过就**拒绝**，不截断 |
| `maxOutputBytes` | 262144（256 KiB） | 渲染结果的软上限；文本按 code point 边界截断并标 `truncated` |
| `maxRawBytes` | 2097152（2 MiB） | 编码工具解码后的原始字节上限 |
| `maxEntries` | 2000 | socket 条目 / issue 列表的上限（计数仍然完整） |
| `maxTextChars` | 200 | `encoding_convert` 回显的解码字符数 |
| `maxFiles` | 20000 | `dir_usage` / `file_duplicates` 的默认文件预算 |
| `maxBytes` | 536870912（512 MiB） | `dir_usage` 的默认记账字节预算 |
| `maxBytesHashed` | 268435456（256 MiB） | `file_duplicates` 的默认哈希预算 |
| `maxErrors` | 50 | 上报的不可读路径条数上限 |
| `toolPrefix` | `""` | 工具名前缀，`win` → `win__path_inspect` |
| `only` | `[]` | 只注册这些工具 |

```yaml
# cordis 配置示例
plugins:
  win-native:
    maxBytesHashed: 1073741824   # 1 GiB
    only: [path_inspect, encoding_detect]
```

**为什么结构化输入超预算要拒绝而不是截断？** 因为截断一个 base64 编码流或者一段 netstat 文本，得到的不是"小一点的结果"，而是**错误的结果**——一半的字节能解码出完全不同的字符，一半的 netstat 表格会漏掉真正的占用者。宁可失败得明确，也不要成功得错误。

## 为什么只依赖 `iconv-lite`

运行期只有一个依赖：`iconv-lite`（`^0.6.3`）。

- **Windows 的码页转换没有 Node 内置替代。** `TextDecoder` 只支持 UTF 系列和少量 `windows-1252` 之类的标签，**不支持 GBK / GB18030 / Big5 / Shift-JIS**——而这恰好是中文 Windows 上 agent 最常撞到的四种编码。`Buffer` 也只支持 `utf8`/`utf16le`/`latin1`/`ascii`/`base64`/`hex`。
- **它没有原生编译。** 纯 JS + 码表数据，不需要 node-gyp、不需要 Visual Studio Build Tools、不需要在安装期联网。这直接满足契约里"不写安装期脚本"的要求——如果引入需要编译的模块，就必然要 `postinstall`，而 pnpm 的 `allowBuilds` 会拦截它。
- **它本来就是 DSH 生态的既成事实。** 很多工具链已经在传递依赖它，所以引入它几乎不增加实际的供应链面。
- **码表行为可验证。** 本插件的编码测试断言了真实字节（GBK `C4E3 BAC3` = "你好"、GBK `C5E4 D6C3` = "配置"），所以如果 iconv-lite 哪天改了码表，测试会先炸，而不是检测逻辑悄悄漂移。

不引入的替代方案都更差：自己维护 GBK/Big5 码表（几 MB 的数据，必然过时）、调 `chcp` + PowerShell（每个进程状态不同，正是本插件要消灭的不确定性）、要求用户预转码（把问题推回给用户）。

## 安装与构建

```powershell
pnpm install
pnpm typecheck
node --test test/
pnpm build
```

`lib/` 是提交进仓库的预构建产物；`dsh.bundle.patch` 指向 `./cordis.patch.yml`，它在配置里插入 `id: win-native`。**没有 `postinstall` / `prepare`**。

## 开发说明

- 源码用 Node 的 **strip-only TypeScript**：相对导入必须写 `.ts` 后缀，不能用构造函数参数属性、`enum`、`namespace`、装饰器。
- `defineTool` 的 const 泛型会在宽 `ParameterSchemaSpec` 联合上递归爆掉（TS2321），所以只有那一处泛型被擦除（`src/tools.ts` 里的单一 cast），参数 DSL 仍然被编译和测试。
- 每个文件系统工具在遍历时逐条检查 `exec.signal.throwIfAborted()`，长遍历每 64 条让出事件循环，所以调用方能取消一个跑在大目录上的统计。

## ROADMAP

**以下能力明确不在 v0.1，因为它们在纯 Node 里无法诚实实现。**

| 能力 | 为什么需要真实 Win32 / Node-API | 为什么不在 v0.1 |
|---|---|---|
| 剪贴板读写 | 需要 `OpenClipboard`/`GetClipboardData` 等 Win32 调用，或用 Electron 的 `clipboard`（本插件不是 Electron 应用） | 没有任何纯 Node 的剪贴板 API。用 PowerShell `Get-Clipboard` 绕路会引入"文本解析 + 每个进程状态不同"，正是本插件反对的做法 |
| 截图 | 需要 GDI / `BitBlt` / `PrintWindow` 或 `desktopCapturer`；`PrintWindow` 还需要处理 DWM 与不同 DPI | 同上。用 PowerShell + .NET 拼可以出图，但依赖宿主装了 .NET 桌面运行时，且无法可靠处理多显示器 / 高 DPI |
| Windows 服务查询与控制 | 需要 `OpenSCManager`/`EnumServicesStatusEx`/`ControlService`；`sc.exe` 的输出是本地化的 | **控制服务是写操作**，与"只读承诺"直接冲突。查询部分可以用 `sc query` 但输出随系统语言变化，解析它就是在编造事实 |
| 进程控制（结束/挂起/优先级） | 需要 `OpenProcess`/`TerminateProcess`/`SetPriorityClass` | v0.1 的全部工具都是只读的，这是本插件相对"ad-hoc PowerShell"的核心优势。破坏性操作应该有独立的、显式的权限模型，不该混进来 |
| 长路径文件操作（`\\?\` 下的创建/枚举/删除） | 需要 `CreateFileW` 等能接受扩展前缀的 API，或 Node 的 libuv 在足够新的版本上支持 | v0.1 提供了 `path_inspect` 的 `canonical` 和 `toExtendedPath`，把"该怎么写"算清楚了；真正**执行**长路径操作需要引入 Node-API 原生模块，会破坏"无安装期脚本" |
| 真实进程/端口归属（哪个进程占着 445） | 需要 `GetExtendedTcpTable` + `QueryFullProcessImageName` | `netstat_parse` 只解析**你给的文本**，并且明确说"PID 是否还活着无法从这段文本判断"。要给出可信答案必须有真实的表 API |

v0.2 会以**独立的一个原生模块**（Node-API / 预编译二进制，按平台分发）来实现这些，让 `dsh-win-native` 的纯 JS 部分保持零编译依赖。任何新工具仍然遵守同一套契约和同一条"如实报告边界"的规则。

## License

MIT © 2026 ax2 — 见 [LICENSE](./LICENSE)。

---

<a id="english"></a>

# English

**The Windows correctness layer: the judgments agents normally fake with ad-hoc PowerShell text parsing, as tools with receipts, budgets, and honest limits.**

## What it is

Six tools. Three of them (`path_inspect`, `netstat_parse`, `encoding_detect`) and `encoding_convert` analyse **input you hand them** and never touch the filesystem. Two (`dir_usage`, `file_duplicates`) **read the local filesystem read-only**. **Nothing in this plugin ever writes, moves, renames, or deletes a file** — including the duplicates it finds; it only reports what could be reclaimed.

| Tool | Reads the filesystem? | Writes? | What it answers |
|---|---|---|---|
| `encoding_detect` | no | no | What encoding are these bytes? BOM → strict UTF-8 → scored code pages, with a confidence of `high`/`medium`/`low` and every close alternative. |
| `encoding_convert` | no | no | Convert between `utf-8`, `utf-16le`, `utf-16be`, `gbk`, `gb18030`, `big5`, `shift_jis`, `latin1`, `ascii`. Reports the exact count and identity of characters the target could not represent. |
| `path_inspect` | no (pure text) | no | Everything that will break a Windows path: extended prefix, UNC vs drive vs rooted vs drive-relative, reserved device names (`CON.txt` included), illegal/control characters, trailing space or dot, 8.3 safety, per-segment length, and 260-char MAX_PATH. Each finding carries a code, a severity, and its position in the original string. |
| `netstat_parse` | no | no | Parses `netstat -ano`/`-anob` or `Get-NetTCPConnection` text: listeners with PID, established connections grouped by remote endpoint, duplicate binds, counts by state and protocol — and refuses to invent liveness, UDP state, or process names the text does not carry. |
| `dir_usage` | **yes, read-only** | no | File/directory counts, total bytes, largest files, extension histogram. `lstat`, so symlinks and junctions are skipped and reported, never followed. |
| `file_duplicates` | **yes, read-only** | no | Groups by size, then streams SHA-256 over same-size candidates only. Reports reclaimable bytes and exactly which files were not hashed when a budget ran out. |

## The two rules that shape everything

1. **Over-budget structured input is refused, never truncated.** Half a base64 stream decodes to different characters; half a netstat table hides the real owner of a port. A clear failure beats a confidently wrong success.
2. **Nothing is assumed.** A budget that stopped the walk sets `truncated` and names the budget. A lossy conversion counts and names its casualties. A directory that could not be opened is a successful result carrying `ENOENT`, not an exception. Paths that cannot be read appear in `unreadable` with their stage and error code. Short CJK payloads are reported as `low` confidence with alternatives, because with real code-page tables a short GBK, Big5, and Shift-JIS payload are genuinely indistinguishable.

## Install

```powershell
pnpm install
pnpm typecheck
node --test test/
pnpm build
```

## License

MIT © 2026 ax2
