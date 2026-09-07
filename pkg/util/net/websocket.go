package net

import (
	"errors"
	"math/rand/v2"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/websocket"
)

var ErrWebsocketListenerClosed = errors.New("websocket listener closed")

const (
	FrpWebsocketPath = "/~!frp"
)

// websocketPathPrefixes and websocketPathSuffixes are used to synthesize a
// random WebSocket path that resembles a common browser endpoint, so that WAFs
// doing path-entropy or blacklist analysis do not flag the fixed "/~!frp" path.
var (
	websocketPathPrefixes = []string{"/ws", "/socket", "/api/ws", "/live", "/stream", "/push", "/notify", "/realtime", "/chat", "/signal"}
	websocketPathSuffixes = []string{"", "-v2", "-h5", "-mobile", "-realtime", "-gateway", "-hub", "-service"}
)

// RandomWebsocketPath returns a random path that looks like a typical browser
// WebSocket endpoint. It is used to avoid the fixed, easily-recognized
// FrpWebsocketPath when the client is configured to randomize its path.
func RandomWebsocketPath() string {
	p := websocketPathPrefixes[rand.IntN(len(websocketPathPrefixes))]
	if rand.IntN(2) == 0 {
		p += websocketPathSuffixes[rand.IntN(len(websocketPathSuffixes))]
	}
	return p
}

type WebsocketListener struct {
	ln       net.Listener
	acceptCh chan net.Conn

	server *http.Server
}

// NewWebsocketListener to handle websocket connections
// ln: tcp listener for websocket connections
func NewWebsocketListener(ln net.Listener) (wl *WebsocketListener) {
	wl = &WebsocketListener{
		ln:       ln,
		acceptCh: make(chan net.Conn),
	}

	// The muxer has already routed the connection to this listener based on the
	// configured WebSocket path prefix, so a catch-all handler is safe here. This
	// lets the client use a custom or randomized path without the server having to
	// know the exact path in advance.
	muxer := http.NewServeMux()
	muxer.Handle("/", websocket.Handler(func(c *websocket.Conn) {
		// The tunnel payload is a raw byte stream (yamux), not UTF-8 text.
		// Send it as binary frames; otherwise RFC 6455-compliant intermediaries
		// (e.g. API gateways/reverse proxies) UTF-8-validate the default text
		// frames and close the connection on invalid bytes.
		c.PayloadType = websocket.BinaryFrame
		notifyCh := make(chan struct{})
		conn := WrapCloseNotifyConn(c, func(_ error) {
			close(notifyCh)
		})
		wl.acceptCh <- conn
		<-notifyCh
	}))

	wl.server = &http.Server{
		Addr:              ln.Addr().String(),
		Handler:           muxer,
		ReadHeaderTimeout: 60 * time.Second,
	}

	go func() {
		_ = wl.server.Serve(ln)
	}()
	return
}

func (p *WebsocketListener) Accept() (net.Conn, error) {
	c, ok := <-p.acceptCh
	if !ok {
		return nil, ErrWebsocketListenerClosed
	}
	return c, nil
}

func (p *WebsocketListener) Close() error {
	return p.server.Close()
}

func (p *WebsocketListener) Addr() net.Addr {
	return p.ln.Addr()
}
