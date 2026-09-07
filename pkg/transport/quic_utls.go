// Copyright 2025 The frp Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package transport

import (
	"context"
	"crypto/tls"

	quic "github.com/quic-go/quic-go"
	utls "github.com/refraction-networking/utls"
)

// utlsQUICConn 将 uTLS 的 UQUICConn 适配为本地 quic-go fork 使用的
// QUICConn 接口，使 QUIC TLS 1.3 握手能由 uTLS 生成 ClientHello。
type utlsQUICConn struct {
	u *utls.UQUICConn
}

// NewUTLSQUICConn 使用指定 uTLS ClientHello ID 创建 quic-go 兼容的 TLS
// 连接。quic-go 通常已克隆配置并设置 MinVersion 为 TLS 1.3；这里仍保留
// 下限检查，避免 UQUICClient 拒绝旧版本配置。
func NewUTLSQUICConn(tlsConf *tls.Config, helloID utls.ClientHelloID) quic.QUICConn {
	cfg := toUTLSConfig(tlsConf)
	if cfg.MinVersion < utls.VersionTLS13 {
		cfg.MinVersion = utls.VersionTLS13
	}
	// uTLS 直接把完成的会话保存到该缓存，无需在 crypto/tls 与 uTLS 的
	// SessionState 私有字段之间转换，即可保留常规会话恢复能力。
	cfg.ClientSessionCache = utls.NewLRUClientSessionCache(32)
	return &utlsQUICConn{
		u: utls.UQUICClient(&utls.QUICConfig{
			TLSConfig:           cfg,
			EnableSessionEvents: true,
		}, helloID),
	}
}

func (c *utlsQUICConn) Start(ctx context.Context) error {
	return c.u.Start(ctx)
}

func (c *utlsQUICConn) NextEvent() tls.QUICEvent {
	e := c.u.NextEvent()
	return tls.QUICEvent{
		Kind:         tls.QUICEventKind(e.Kind),
		Level:        tls.QUICEncryptionLevel(e.Level),
		Data:         e.Data,
		Suite:        e.Suite,
		SessionState: nil,
	}
}

func (c *utlsQUICConn) HandleData(level tls.QUICEncryptionLevel, data []byte) error {
	return c.u.HandleData(utls.QUICEncryptionLevel(level), data)
}

func (c *utlsQUICConn) Close() error {
	return c.u.Close()
}

func (c *utlsQUICConn) SetTransportParameters(params []byte) {
	c.u.SetTransportParameters(params)
}

// StoreSession 有意保持 no-op。当前 uTLS 版本不会向 quic-go 传播会话事件，
// 会话缓存已在 NewUTLSQUICConn 中交给 uTLS 管理，因此常规会话恢复仍可用。
func (c *utlsQUICConn) StoreSession(*tls.SessionState) error {
	return nil
}

func (c *utlsQUICConn) SendSessionTicket(opts tls.QUICSessionTicketOptions) error {
	return c.u.SendSessionTicket(utls.QUICSessionTicketOptions{
		EarlyData: opts.EarlyData,
		Extra:     opts.Extra,
	})
}

func (c *utlsQUICConn) ConnectionState() tls.ConnectionState {
	uState := c.u.ConnectionState()
	return tls.ConnectionState{
		Version:                     uState.Version,
		HandshakeComplete:           uState.HandshakeComplete,
		DidResume:                   uState.DidResume,
		CipherSuite:                 uState.CipherSuite,
		NegotiatedProtocol:          uState.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  uState.NegotiatedProtocolIsMutual,
		ServerName:                  uState.ServerName,
		PeerCertificates:            uState.PeerCertificates,
		VerifiedChains:              uState.VerifiedChains,
		SignedCertificateTimestamps: uState.SignedCertificateTimestamps,
		OCSPResponse:                uState.OCSPResponse,
		TLSUnique:                   uState.TLSUnique,
	}
}
