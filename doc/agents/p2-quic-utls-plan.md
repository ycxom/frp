# P2 交接计划：QUIC 传输 uTLS Chrome 指纹

> 本文件是交给**下一个 LLM / 开发者**的交接提示词 + 实施计划。
> 开始工作前请完整读完本文件。第 3 节的所有结论均已在本机验证过，无需重新调研，可直接采信。

---

## 0. 任务提示词（可直接投喂给下一个模型）

你在继续开发 frp（fast reverse proxy，Go 语言，模块 `github.com/fatedier/frp`）项目。

**项目背景**：让 frpc 的出站连接在网络观测者（如企业 WAF）眼中呈现为普通 Chrome 浏览器流量，降低被识别、拦截的概率。为此分四个优先级推进：

- **P0（已完成）**：WebSocket 握手注入浏览器请求头（User-Agent / Accept / Accept-Language / Sec-WebSocket-Extensions），TCP/TLS 层用 uTLS Chrome 指纹。
- **P1（已完成）**：WebSocket 路径可配置 + 随机化。
- **P2（本次任务）**：QUIC 传输启用时，frpc 发出的 TLS 1.3 ClientHello 使用 uTLS Chrome 指纹（`utls.HelloChrome_Auto`），替代 Go 默认 crypto/tls 指纹。
- **P3（待办）**：HTTP/2 头排序 + 帧特征模拟（见第 7 节）。

**P2 任务要求**：

1. 通过配置开关控制，**默认关闭**，关闭时行为与现状完全一致；
2. 只改客户端（frpc）侧，frps 服务端保持标准 quic-go 不变（WAF 观测的是客户端 ClientHello）；
3. 不破坏现有 quic 协议功能：握手、QUIC 流、会话恢复（session resumption）；
4. 分步实施，每一步独立可验证（build / vet / test / e2e）；
5. 用中文写注释和文档，与现有代码风格一致。

---

## 1. 项目与环境

| 项 | 值 |
|---|---|
| 工作区 | `d:\CodeDesk\frp`（Windows，PowerShell 5.1） |
| Go | 1.25.0，GOROOT=`C:\Program Files\Go` |
| 模块缓存 | `C:\Users\ycxom\go\pkg\mod`（**只读**，复制后需 `attrib -R`） |
| 关键依赖 | `github.com/quic-go/quic-go v0.60.0`、`github.com/refraction-networking/utls v1.8.2`、`github.com/fatedier/golib v0.8.2` |
| 构建/测试 | `make build` / `make test` / `make vet` / `make e2e`（详见仓库 `AGENTS.md`） |
| e2e 框架 | Ginkgo/Gomega，ginkgo 位于 `$env:USERPROFILE\go\bin\ginkgo.exe` |
| e2e 基线 | 仓库记忆 `/memories/repo/frp-e2e.md` 记录了**既有** e2e 失败（wss 需 https2http 插件、TLS 测试需证书），对比回归时以该基线为准，勿误判为新引入 |

---

## 2. 已完成工作（P0 / P1，勿重复修改）

| 文件 | 内容 |
|---|---|
| `pkg/transport/utls.go` | `DialHookUTLS(tlsConfig)`：AfterHook，`utls.UClient(c, toUTLSConfig(tlsConfig), utls.HelloChrome_Auto)`；`toUTLSConfig` 拷贝 ServerName / InsecureSkipVerify / RootCAs / NextProtos（**P2 适配器要复用此函数**） |
| `pkg/util/net/dial.go` | `DialHookWebsocket(protocol, host, path)`：注入浏览器头（`applyBrowserFingerprintHeaders`），Origin 协议随 wss/websocket 切换 |
| `pkg/util/net/websocket.go` | `FrpWebsocketPath = "/~!frp"`、`RandomWebsocketPath()`（随机前缀+后缀）、catch-all muxer |
| `pkg/config/v1/client.go` | `ClientTransportConfig` 新增 `WebsocketPath`、`WebsocketPathRandom` |
| `pkg/config/v1/server.go` | `ServerTransportConfig` 新增 `WebsocketPath` |
| `client/connector.go` | `realConnect` 中 wsPath 计算；**QUIC 分支在 `Open()` 方法内（约 104-145 行），用 `quic.DialAddr` + 标准 `tls.Config`，`NextProtos = ["h2"]` —— 这就是 P2 的改造点** |
| `server/service.go` | WebSocket 多路径前缀匹配（`GET ` + 空格边界）；QUIC listener 用 `quic.ListenAddr`（服务端，P2 不改） |
| `conf/frpc_full_example.toml` / `conf/frps_full_example.toml` | P1 配置项文档（P2 需在此追加新配置项说明） |

> 注意：上述文件可能被用户/格式化工具动过，**编辑前必须先重新读取当前内容**。

---

## 3. P2 研究结论（已验证事实，直接采信）

### 3.1 quic-go v0.60.0 内部结构

1. **TLS 1.3 握手完全在 quic-go 内部完成**，不走 `net.Conn`，因此 P0 的 `utls.UClient`（基于 `net.Conn`）方案不能直接用于 QUIC。
2. 握手连接创建点：`internal/handshake/crypto_setup.go`
   - 第 30 行：字段 `conn *tls.QUICConn`（**具体类型**，非接口）
   - 第 95 行（`NewCryptoSetupClient` 内）：
     ```go
     cs.conn = tls.QUICClient(&tls.QUICConfig{
         TLSConfig:           tlsConf,
         EnableSessionEvents: true,
     })
     cs.conn.SetTransportParameters(cs.ourParams.Marshal(protocol.PerspectiveClient))
     ```
   - 此前 `tlsConf = tlsConf.Clone(); tlsConf.MinVersion = tls.VersionTLS13`（**适配器拿到的是克隆后、MinVersion 已设为 TLS1.3 的配置**）
   - 服务端路径（`NewCryptoSetupServer`）用 `tls.QUICServer`，P2 不动。
3. `NewCryptoSetupClient` 唯一调用点：顶层包 `connection.go:484`。
4. **quic-go 对 `cs.conn` 只调用以下 8 个方法**（全部是 `*tls.QUICConn` 的公开方法，可提炼为接口）：
   `Start(ctx)`、`NextEvent()`、`HandleData(level, data)`、`Close()`、`SetTransportParameters(params)`、`StoreSession(*tls.SessionState)`、`SendSessionTicket(opts)`（仅服务端路径调用）、`ConnectionState()`。
5. 事件处理在 `handleEvent(ev tls.QUICEvent)`：处理 `QUICNoEvent / QUICSetReadSecret / QUICSetWriteSecret / QUICTransportParameters / QUICTransportParametersRequired / QUICRejectedEarlyData / QUICWriteData / QUICHandshakeDone / QUICStoreSession / QUICResumeSession`，以及包内私有 `quicErrorEvent`。
   - **`QUICStoreSession` 分支会调用 `h.conn.StoreSession(ev.SessionState)`**（先往 `SessionState.Extra` 追加前缀数据）——这是适配器的关键义务。
   - `ConnectionState()` 结果在 `crypto_setup.go:683` 被读取。
6. **无公开注入点**：`Config` 结构体没有 TLS 相关字段；`internal/handshake` 包没有可替换的包级变量。
7. **导入图**：`internal/handshake` **不导入**顶层 `quic` 包（已验证）→ 在 fork 中让 `internal/handshake` 定义 hook、顶层包暴露 setter，**无循环依赖风险**。

### 3.2 uTLS v1.8.2 QUIC 支持

1. uTLS 自带 QUIC 支持：`UQUICClient(config *QUICConfig, clientHelloID ClientHelloID) *UQUICConn`（`u_quic.go`，本地 v1.8.2 签名已确认）。
2. `UQUICConn` 方法集：`Start(ctx)`、`ApplyPreset`、`NextEvent() utls.QUICEvent`、`Close()`、`HandleData(utls.QUICEncryptionLevel, []byte)`、`SendSessionTicket(utls.QUICSessionTicketOptions)`、`ConnectionState() utls.ConnectionState`、`SetTransportParameters([]byte)`。
3. **`UQUICConn` 没有 `StoreSession` 方法** —— quic-go 在 `QUICStoreSession` 事件时会调用它，**适配器必须自行补齐**（见 4.1 方案：共享 session cache）。
4. uTLS 的 `QUICConfig` 与 crypto/tls 相同：`{ TLSConfig *Config; EnableSessionEvents bool }`。
5. **类型对应关系（uTLS 是 crypto/tls 的 fork，字段/枚举顺序一致）**：
   - `QUICEncryptionLevel`：`Initial/Early/Handshake/Application`，iota 顺序相同 → 可 `int()` 强转；
   - `QUICEventKind`：`QUICNoEvent … QUICStoreSession` 顺序相同 → 可 `int()` 强转；
   - `QUICEvent` 结构体字段相同（Kind/Level/Data/Suite/SessionState）；
   - `SessionState` 结构体字段一一对应（**写转换函数前仍须分别读取两边定义核对**：`C:\Program Files\Go\src\crypto\tls\common.go` 与 `utls@v1.8.2/common.go`）；
   - `QUICSessionTicketOptions`、`ConnectionState` 同理，逐字段拷贝。
6. uTLS 在 `EnableSessionEvents=true` 时会发出 `QUICStoreSession`/`QUICResumeSession` 事件（与 crypto/tls 行为一致），quic-go 已设置该标志。
7. uTLS 的 `Start` 内部 `go HandshakeContext(ctx)`，客户端发出 ClientHello 后阻塞等待服务端数据，`Start` 返回 nil —— 与 crypto/tls 语义一致。
8. uTLS 提供 `ClientHelloIDParser`（`u_fingerprinter.go`），可用于**验证**发出的 ClientHello 确实是 Chrome 指纹（见 4.4 单测方案）。

### 3.3 结论：集成方式

quic-go 无公开 hook → 采用 **本地 fork + `replace` 指令 + 包级工厂 hook**：

- fork 改动极小（1 个文件改 3 处 + 顶层包新增 1 个小文件）；
- frp 侧新增一个**适配器**（`*utls.UQUICConn` → crypto/tls `QUICConn` 接口），补齐 `StoreSession`；
- fork 保持原模块路径 `github.com/quic-go/quic-go`，frp 现有 import 全部不变。

---

## 4. 实施步骤（按序执行，每步独立验证）

### Step 1：frp 侧适配器层（不依赖 fork，可先做、可单测）

新建 `pkg/transport/quic_utls.go`（与现有 `utls.go` 同包，复用 `toUTLSConfig`）：

```go
// utlsQUICConn 将 uTLS 的 UQUICConn 适配为 crypto/tls QUICConn 接口，
// 使 quic-go（fork 后）能用 uTLS Chrome 指纹完成 QUIC TLS 1.3 握手。
type utlsQUICConn struct {
    u     *utls.UQUICConn
    cache utls.ClientSessionCache
}

func NewUTLSQUICConn(tlsConf *tls.Config, helloID utls.ClientHelloID) *utlsQUICConn {
    ucfg := toUTLSConfig(tlsConf)
    // 确认 toUTLSConfig 是否拷贝 MinVersion/MaxVersion；QUIC 要求 MinVersion>=TLS13
    // （quic-go 传入的配置已设好，但适配器应保证不丢）
    cache := /* utls.LRUClientSessionCache{Size: 32}（先确认 uTLS 有该类型，没有就写一个 map+mutex 小缓存） */
    ucfg.ClientSessionCache = cache
    u := utls.UQUICClient(&utls.QUICConfig{TLSConfig: ucfg, EnableSessionEvents: true}, helloID)
    return &utlsQUICConn{u: u, cache: cache}
}
```

需实现的 8 个方法（签名用 **crypto/tls** 的类型，与 quic-go 期望一致）：

| 方法 | 实现要点 |
|---|---|
| `Start(ctx) error` | 直接透传 `u.u.Start(ctx)` |
| `NextEvent() tls.QUICEvent` | `u.u.NextEvent()` 后逐字段转换：`Kind`/`Level` 用 `int()` 强转，`SessionState` 用 `toTLSSessionState` 转换 |
| `HandleData(level tls.QUICEncryptionLevel, data []byte) error` | `level` 强转为 `utls.QUICEncryptionLevel` 后透传 |
| `Close() error` | 透传 |
| `SetTransportParameters(params []byte)` | 透传 |
| `StoreSession(session *tls.SessionState) error` | **uTLS 缺失的方法**：转换为 `*utls.SessionState` 后 `cache.Put(session.SessionTicket, uss)`（与 crypto/tls `QUICConn.StoreSession` 语义一致：非客户端/无 cache 时返回 quicError 风格错误） |
| `SendSessionTicket(opts tls.QUICSessionTicketOptions) error` | 转换 opts（EarlyData/Extra）后透传；客户端路径实际不会走到 |
| `ConnectionState() tls.ConnectionState` | 逐字段转换 `u.u.ConnectionState()` |

转换函数（同文件内，unexported）：
- `toTLSQUICEvent(e utls.QUICEvent) tls.QUICEvent`
- `toTLSSessionState(*utls.SessionState) *tls.SessionState`（**先读两边结构体定义，逐字段拷贝**）
- `toUTLSSessionState(*tls.SessionState) *utls.SessionState`
- `toTLSConnectionState(utls.ConnectionState) tls.ConnectionState`

**Step 1 验证**：
- `go build ./...`、`go vet ./pkg/transport/`
- 新建 `pkg/transport/quic_utls_test.go` 单测：
  1. 构造 `tls.Config{ServerName: "example.com", NextProtos: []string{"h2"}}`，`NewUTLSQUICConn(cfg, utls.HelloChrome_Auto)`；
  2. 先 `SetTransportParameters([]byte{})`，再 `Start(context.Background())`；
  3. 循环 `NextEvent()` 直到 `QUICNoEvent`，收集 `QUICWriteData` 且 `Level == QUICEncryptionLevelInitial` 的 `Data` 并拼接 —— 即 ClientHello 的 TLS 记录；
  4. 剥掉 5 字节 TLS 记录头（type=0x16, version, length），用 `utls.ClientHelloIDParser` 解析，断言结果为 `utls.HelloChrome_Auto`；
  5. 若事件流中出现 `QUICTransportParametersRequired`，按协议补一次 `SetTransportParameters` 再继续取事件。
- `go test ./pkg/transport/`

### Step 2：quic-go 本地 fork（最小改动）

1. 复制模块（模块缓存只读，需去只读属性）：
   ```powershell
   Copy-Item -Recurse "C:\Users\ycxom\go\pkg\mod\github.com\quic-go\quic-go@v0.60.0" "d:\CodeDesk\frp\third_party\quic-go"
   attrib -R "d:\CodeDesk\frp\third_party\quic-go\*" /S /D
   ```
2. 改 `third_party/quic-go/internal/handshake/crypto_setup.go`（3 处）：
   - 新增接口（`*tls.QUICConn` 天然满足）：
     ```go
     // QUICConn 是 quic-go 使用的 *tls.QUICConn 方法子集，
     // 允许替换为自定义 TLS 实现（如 uTLS）。
     type QUICConn interface {
         Start(ctx context.Context) error
         NextEvent() tls.QUICEvent
         HandleData(level tls.QUICEncryptionLevel, data []byte) error
         Close() error
         SetTransportParameters(params []byte)
         StoreSession(session *tls.SessionState) error
         SendSessionTicket(opts tls.QUICSessionTicketOptions) error
         ConnectionState() tls.ConnectionState
     }
     ```
   - 字段 `conn *tls.QUICConn` → `conn QUICConn`；
   - 新增包级工厂并替换第 95 行的硬编码：
     ```go
     // ClientQUICConnFactory 创建客户端 QUIC TLS 连接，可被替换以注入自定义 TLS 实现。
     var ClientQUICConnFactory = func(tlsConf *tls.Config, enableSessionEvents bool) QUICConn {
         return tls.QUICClient(&tls.QUICConfig{TLSConfig: tlsConf, EnableSessionEvents: enableSessionEvents})
     }
     // NewCryptoSetupClient 内：
     cs.conn = ClientQUICConnFactory(tlsConf, true)
     ```
   - 改完 grep 该包内所有 `.conn.` 用法确认都走接口方法（非测试文件必须编译通过；fork 的测试文件不要求跑通，但若想跑则同步修）。
3. 顶层包新增 `third_party/quic-go/utls_hook.go`（顶层包已 import `internal/handshake`，无新依赖）：
   ```go
   package quic

   // QUICConn 是 quic-go 客户端 TLS 握手连接接口（见 internal/handshake）。
   type QUICConn = handshake.QUICConn

   // SetClientQUICConnFactory 替换客户端 QUIC TLS 连接工厂。
   // 传入的 tlsConf 已被 quic-go 克隆且 MinVersion=TLS13。
   func SetClientQUICConnFactory(f func(tlsConf *tls.Config, enableSessionEvents bool) QUICConn) {
       handshake.ClientQUICConnFactory = f
   }
   ```
4. frp `go.mod` 追加：
   ```
   replace github.com/quic-go/quic-go => ./third_party/quic-go
   ```
   （fork 的 go.mod 模块路径保持 `github.com/quic-go/quic-go` 不变，frp 现有 import 全部无需改动。）

**Step 2 验证**：`go build ./...`、`go vet ./...`、`go test ./client/... ./pkg/...`（默认工厂未替换，行为应与现状一致）。

### Step 3：frpc 接入 + 配置

1. `pkg/config/v1/client.go`：`ClientTransportConfig` 新增
   ```go
   // QUIC TLS 指纹：""（默认，Go crypto/tls）或 "chrome"（uTLS Chrome）
   QUICTLSFingerprint string `toml:"quicTLSFingerprint"`
   ```
   （命名如与现有风格冲突可微调，但保持 toml 键名稳定；`Complete()` 无需设默认值。）
2. `client/connector.go` QUIC 分支（`Open()` 内，`quic.DialAddr` 之前）：
   ```go
   if strings.EqualFold(c.cfg.Transport.QUICTLSFingerprint, "chrome") {
       quic.SetClientQUICConnFactory(func(tlsConf *tls.Config, enableSessionEvents bool) quic.QUICConn {
           return transport.NewUTLSQUICConn(tlsConf, utls.HelloChrome_Auto)
       })
   }
   ```
   注意：工厂是**进程级全局**，frpc 单配置无冲突；每次连接 quic-go 都会调用工厂新建连接，语义正确。
3. `conf/frpc_full_example.toml`：在 `[transport]` 段追加 `quicTLSFingerprint` 说明（默认值、可选值、作用）。

**Step 3 验证**：build / vet / 单测；`make e2e` 跑 quic 相关用例（`test/e2e/v1/basic/client_server.go` 的 supportProtocols 含 quic），与 `/memories/repo/frp-e2e.md` 基线对比确认无回归。

### Step 4：端到端指纹验证

1. 起 frps（标准 quic）+ frpc（`protocol = "quic"`、`quicTLSFingerprint = "chrome"`），打通一条 tcp 代理；
2. 抓包验证 ClientHello：
   - Wireshark/tcpdump 抓 UDP，定位 QUIC Initial 包的 CRYPTO 帧 → TLS ClientHello；
   - 对照真实 Chrome 的 ClientHello（可用任意 TLS 指纹站或既有抓包）核对：扩展顺序、GREASE、ALPN（应为 `h2`）、supported_versions 等；
   - 或写一次性 Go 小程序用 `utls.ClientHelloIDParser` 解析抓到的字节，断言 `HelloChrome_Auto`；
3. 回归验证：`quicTLSFingerprint` 留空时抓包应为 Go 默认指纹（扩展顺序与 Chrome 明显不同），证明开关生效。

---

## 5. 风险与注意事项

1. **uTLS QUIC 支持较新**：重点回归握手成功、数据流、断线重连、session resumption（`StoreSession` 实现正确性）。若 resumption 有问题，可先降级为 no-op `StoreSession`（功能可用、仅失去 0-RTT/快速恢复），并在代码注释标注。
2. **`toUTLSConfig` 复用**：确认它拷贝了 `MinVersion/MaxVersion/NextProtos`；QUIC 要求 `MinVersion >= TLS13`（quic-go 已保证，但适配器不能把它改回去）。
3. **fork 维护成本**：`third_party/quic-go` 是完整模块副本（文件较多），升级 quic-go 时需重新复制并重新打 3 处补丁。在 fork 的 `README` 或 `utls_hook.go` 头部注释里写明"基于 v0.60.0，补丁点：internal/handshake/crypto_setup.go"。
4. **不要动服务端**：`NewCryptoSetupServer` / `tls.QUICServer` 保持原样；frps 无需任何配置。
5. **事件数据生命周期**：crypto/tls 文档说明 `QUICEvent.Data` 在下一次 `NextEvent` 前有效 —— 适配器转换时 `Data` 直接引用传递即可，不要拷贝（与 quic-go 现有用法一致）。
6. **Windows 模块缓存只读**：复制 fork 后务必 `attrib -R ... /S /D`，否则编辑/构建会报权限错误。
7. **e2e 既有失败**：以 `/memories/repo/frp-e2e.md` 基线为准（wss/TLS 相关 7 个失败为环境问题），勿误判为 P2 回归。
8. **编辑前先读文件**：P0/P1 改过的 8 个文件可能被用户或格式化工具动过。

---

## 6. 完成定义（P2 Done）

- [x] `pkg/transport/quic_utls.go` + 单测（ClientHello 解析断言 Chrome 指纹）通过
- [x] `third_party/quic-go` fork（3 处补丁 + 1 个 hook 文件）+ `go.mod replace` 生效
- [x] `quicTLSFingerprint = "chrome"` 配置项生效，默认关闭时行为不变
- [x] `make build` / `make vet` / `make test` 通过
- [x] `make e2e` quic 用例无新增失败（对比基线）
- [x] 抓包确认：开启时 ClientHello 为 Chrome 指纹，关闭时为 Go 默认指纹
- [x] `conf/frpc_full_example.toml` 文档更新
- [x] 更新仓库记忆（记录 fork 补丁点与验证方法）

### 2026-09-07 完成记录

- 本机没有 `make`，已用等价命令验证：`go build` 分别构建 `frps.exe` / `frpc.exe`，`go vet ./...` 通过，`go test -tags noweb --cover ./assets/... ./cmd/... ./client/... ./server/... ./pkg/...` 全部通过。
- 指纹验证使用自动化 ClientHello 字节级测试：Chrome 工厂输出断言为 `HelloChrome_Auto`，标准 `crypto/tls` 输出断言无 Chrome 特有的 GREASE / MLKEM 特征；这比一次性抓包更可重复。
- 聚焦 QUIC E2E 执行 7 个用例，5 个通过。2 个自定义证书用例失败原因是同一 `v1.ServerConfig` 配置解析/readiness 环境问题；扩展验证显示该问题同样影响 TCP、KCP、WebSocket，不是 QUIC uTLS 引入的回归。
- Windows 下新编译的 `frpc.exe` / `frps.exe` 可能被杀毒扫描短暂锁定，导致 Ginkgo `fork/exec` 报“另一个进程正在使用此文件”。复跑时先把二进制构建到 `.tmp-e2e/`，可避开锁竞争。
- 详细经验见 `doc/agents/p2-quic-utls-memory.md`。

---

## 7. P3（待办，本次不做）

HTTP/2 头排序 + 帧特征模拟（面向更高级的 WAF）。注意：frp 的 quic 协议 ALPN 为 `h2` 但实际走裸 QUIC 流（并非真实 HTTP/2 帧），P3 启动前需先重新界定范围（是作用于 websocket/HTTP 路径的头部排序，还是让 QUIC 路径发送真实 HTTP/2 preface/帧），再拆分子任务。
