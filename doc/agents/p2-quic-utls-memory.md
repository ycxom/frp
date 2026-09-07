# P2 QUIC uTLS 仓库记忆

## 实现记录

- QUIC 客户端 TLS 工厂补丁位于本地 fork 的 `third_party/quic-go/internal/handshake/crypto_setup.go`；顶层入口与 getter 位于 `third_party/quic-go/utls_hook.go`。
- frp 通过 `go.mod` 的 `replace github.com/quic-go/quic-go => ./third_party/quic-go` 使用 fork。升级 quic-go 时需要重新打补丁，并保持 `ClientQUICConnFactoryFunc` 类型别名和工厂 getter 可用。
- frp 适配器是 `pkg/transport/quic_utls.go`。它把 uTLS `UQUICConn` 转换为 crypto/tls QUIC 事件接口，并补齐 quic-go 需要的 `StoreSession` 语义。
- 客户端接入点在 `client/connector.go` 的 QUIC 分支。只有 `transport.quicTLSFingerprint = "chrome"` 时替换进程级工厂；空值保持标准 `crypto/tls` 行为，其他值在打开连接前报错。

## 可重复验证

```powershell
go test ./pkg/transport/ ./pkg/config/... ./client/
go vet ./...
go test -tags noweb --cover ./assets/... ./cmd/... ./client/... ./server/... ./pkg/...
```

`pkg/transport/quic_utls_test.go` 会采集 QUIC Initial 阶段的 ClientHello 字节并解析：

- Chrome 工厂断言命中 `utls.HelloChrome_Auto`，并包含 GREASE 和 MLKEM 特征。
- 标准 `crypto/tls` QUIC 连接断言没有这些 Chrome 特征，用来证明开关关闭时行为不变。

## Windows E2E 注意事项

聚焦 QUIC 用例可使用：

```powershell
ginkgo -nodes=1 -focus="quic" D:/CodeDesk/frp/test/e2e -- `
  -frpc-path D:/CodeDesk/frp/.tmp-e2e/frpc.exe `
  -frps-path D:/CodeDesk/frp/.tmp-e2e/frps.exe `
  -log-level debug -debug=true
```

- Ginkgo 的二进制路径参数在 Windows PowerShell 中使用空格分隔比 `=` 形式更可靠。
- 新编译的 `frpc.exe` / `frps.exe` 可能被杀毒软件短暂锁定，`fork/exec` 会报文件被占用。先构建到 `.tmp-e2e/`，再让 E2E 使用该副本。
- 2026-09-07 聚焦 QUIC：7 个用例中 5 个通过；2 个自定义证书用例的 `v1.ServerConfig` 解析/readiness 失败同样出现在 TCP、KCP、WebSocket，应视为既有环境/测试基线问题，而不是 QUIC uTLS 回归。
