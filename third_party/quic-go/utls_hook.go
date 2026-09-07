package quic

import (
	"crypto/tls"

	"github.com/quic-go/quic-go/internal/handshake"
)

// QUICConn 是 quic-go 期望的客户端 TLS 连接接口。
type QUICConn = handshake.QUICConn

// ClientQUICConnFactoryFunc 是客户端 QUIC TLS 连接工厂的类型。
type ClientQUICConnFactoryFunc = handshake.ClientQUICConnFactoryFunc

// GetClientQUICConnFactory 返回当前客户端 QUIC TLS 连接工厂。
func GetClientQUICConnFactory() ClientQUICConnFactoryFunc {
	return handshake.ClientQUICConnFactory
}

// SetClientQUICConnFactory 替换客户端 QUIC TLS 连接工厂，可注入 uTLS 等
// 自定义 TLS 实现，同时保留 quic-go 的连接与会话处理逻辑。
//
// 本地 fork 基于 quic-go v0.60.0；补丁点是
// internal/handshake/crypto_setup.go，升级时需重新套用。
func SetClientQUICConnFactory(f func(tlsConf *tls.Config, enableSessionEvents bool) QUICConn) {
	handshake.ClientQUICConnFactory = f
}
