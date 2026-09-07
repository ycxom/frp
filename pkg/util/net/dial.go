package net

import (
	"context"
	"net"
	"net/http"
	"net/url"

	libnet "github.com/fatedier/golib/net"
	"golang.org/x/net/websocket"
)

func DialHookCustomTLSHeadByte(enableTLS bool, disableCustomTLSHeadByte bool) libnet.AfterHookFunc {
	return func(ctx context.Context, c net.Conn, addr string) (context.Context, net.Conn, error) {
		if enableTLS && !disableCustomTLSHeadByte {
			_, err := c.Write([]byte{byte(FRPTLSHeadByte)})
			if err != nil {
				return nil, nil, err
			}
		}
		return ctx, c, nil
	}
}

// DialHookWebsocket returns an AfterHook that upgrades the raw connection to a
// WebSocket tunnel. path is the request path used in the upgrade request; when
// empty it falls back to the default FrpWebsocketPath. Passing a custom or
// randomized path lets the client avoid the fixed, easily-recognized default.
func DialHookWebsocket(protocol string, host string, path string) libnet.AfterHookFunc {
	return func(ctx context.Context, c net.Conn, addr string) (context.Context, net.Conn, error) {
		if protocol != "wss" {
			protocol = "ws"
		}
		if host == "" {
			host = addr
		}
		if path == "" {
			path = FrpWebsocketPath
		}
		addr = protocol + "://" + host + path
		uri, err := url.Parse(addr)
		if err != nil {
			return nil, nil, err
		}

		// A wss connection must present an https:// origin; using http:// on an
		// encrypted channel is an obvious non-browser tell.
		originScheme := "http"
		if protocol == "wss" {
			originScheme = "https"
		}
		origin := originScheme + "://" + uri.Host
		cfg, err := websocket.NewConfig(addr, origin)
		if err != nil {
			return nil, nil, err
		}
		// Make the upgrade request look like a real browser to WAFs that
		// fingerprint the WebSocket handshake.
		applyBrowserFingerprintHeaders(cfg.Header)

		conn, err := websocket.NewClient(cfg, c)
		if err != nil {
			return nil, nil, err
		}
		// The tunnel payload is a raw byte stream (yamux), not UTF-8 text.
		// Send it as binary frames; otherwise RFC 6455-compliant intermediaries
		// (e.g. API gateways/reverse proxies) UTF-8-validate the default text
		// frames and close the connection on invalid bytes.
		conn.PayloadType = websocket.BinaryFrame
		return ctx, conn, nil
	}
}

// applyBrowserFingerprintHeaders populates the WebSocket upgrade request with the
// headers a real browser sends, so that WAFs fingerprinting the handshake do not
// flag the connection as non-browser traffic.
//
// These headers are written by the x/net/websocket client via
// Header.WriteSubset(bw, handshakeHeader), where handshakeHeader is an *exclude*
// set (only Host/Upgrade/Connection/Sec-Websocket-* are suppressed). None of the
// headers below are in that set, so they pass through to the wire.
//
// Sec-WebSocket-Extensions is safe to advertise: the frp server (x/net/websocket
// hybiServerHandshaker) does not echo it back, so the client's
// ErrUnsupportedExtensions check is not triggered.
func applyBrowserFingerprintHeaders(h http.Header) {
	h.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	h.Set("Accept", "*/*")
	h.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	h.Set("Accept-Encoding", "gzip, deflate, br")
	h.Set("Sec-WebSocket-Extensions", "permessage-deflate; client_max_window_bits")
}
