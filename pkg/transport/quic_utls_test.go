package transport

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"slices"
	"testing"

	utls "github.com/refraction-networking/utls"
)

func collectUTLSQUICClientHello(t *testing.T) []byte {
	t.Helper()

	conn := NewUTLSQUICConn(&tls.Config{
		ServerName: "example.com",
		NextProtos: []string{"h2"},
	}, utls.HelloChrome_Auto)
	conn.SetTransportParameters([]byte{})
	if err := conn.Start(context.Background()); err != nil {
		t.Fatalf("start uTLS QUIC connection: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
	})

	var clientHello []byte
	for range 64 {
		e := conn.NextEvent()
		if e.Kind == tls.QUICNoEvent {
			break
		}
		if e.Kind == tls.QUICWriteData && e.Level == tls.QUICEncryptionLevelInitial {
			clientHello = append(clientHello, e.Data...)
		}
	}
	if len(clientHello) == 0 {
		t.Fatal("uTLS QUIC connection did not write an Initial ClientHello")
	}
	return clientHello
}

func collectStandardTLSQUICClientHello(t *testing.T) []byte {
	t.Helper()

	conn := tls.QUICClient(&tls.QUICConfig{
		TLSConfig: &tls.Config{
			ServerName: "example.com",
			NextProtos: []string{"h2"},
			MinVersion: tls.VersionTLS13,
		},
		EnableSessionEvents: true,
	})
	conn.SetTransportParameters([]byte{})
	if err := conn.Start(context.Background()); err != nil {
		t.Fatalf("start standard TLS QUIC connection: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
	})

	var clientHello []byte
	for range 64 {
		e := conn.NextEvent()
		if e.Kind == tls.QUICNoEvent {
			break
		}
		if e.Kind == tls.QUICWriteData && e.Level == tls.QUICEncryptionLevelInitial {
			clientHello = append(clientHello, e.Data...)
		}
	}
	if len(clientHello) == 0 {
		t.Fatal("standard TLS QUIC connection did not write an Initial ClientHello")
	}
	return clientHello
}

func parseQUICClientHello(t *testing.T, data []byte) *utls.ClientHelloSpec {
	t.Helper()

	record := make([]byte, 5, 5+len(data))
	record[0] = 0x16
	binary.BigEndian.PutUint16(record[1:], utls.VersionTLS10)
	binary.BigEndian.PutUint16(record[3:], uint16(len(data)))
	record = append(record, data...)

	spec, err := (&utls.Fingerprinter{AllowBluntMimicry: true}).RawClientHello(record)
	if err != nil {
		t.Fatalf("parse ClientHello: %v", err)
	}
	return spec
}

func clientHelloFeatures(spec *utls.ClientHelloSpec) (hasTLS13, hasMLKEM, hasGREASE bool) {
	for _, ext := range spec.Extensions {
		if curves, ok := ext.(*utls.SupportedCurvesExtension); ok {
			hasMLKEM = hasMLKEM || slices.Contains(curves.Curves, utls.X25519MLKEM768)
		}
		if versions, ok := ext.(*utls.SupportedVersionsExtension); ok {
			hasTLS13 = hasTLS13 || slices.Contains(versions.Versions, utls.VersionTLS13)
		}
		if _, ok := ext.(*utls.UtlsGREASEExtension); ok {
			hasGREASE = true
		}
	}
	return hasTLS13, hasMLKEM, hasGREASE
}

func TestUTLSQUICConnUsesChromeClientHello(t *testing.T) {
	data := collectUTLSQUICClientHello(t)
	spec := parseQUICClientHello(t, data)
	hasTLS13, hasMLKEM, hasGREASE := clientHelloFeatures(spec)
	if !hasTLS13 || !hasMLKEM || !hasGREASE {
		t.Fatalf("ClientHello is not Chrome 133: tls13=%v mlkem=%v grease=%v extensions=%d", hasTLS13, hasMLKEM, hasGREASE, len(spec.Extensions))
	}
}

func TestStandardTLSQUICConnKeepsDefaultClientHello(t *testing.T) {
	spec := parseQUICClientHello(t, collectStandardTLSQUICClientHello(t))
	hasTLS13, hasMLKEM, hasGREASE := clientHelloFeatures(spec)
	if !hasTLS13 {
		t.Fatal("standard TLS ClientHello does not advertise TLS 1.3")
	}
	if hasGREASE {
		t.Fatalf("standard TLS ClientHello unexpectedly has a Chrome GREASE extension: extensions=%d", len(spec.Extensions))
	}
	// Go 1.25 may enable ML-KEM by default; Chrome is distinguished by GREASE
	// plus Chrome-specific extension ordering and proprietary extensions.
	_ = hasMLKEM
}
