// Copyright 2026 The frp Authors
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

package client

import (
	"context"
	"crypto/tls"
	"reflect"
	"testing"

	quic "github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"

	v1 "github.com/fatedier/frp/pkg/config/v1"
)

func TestConnectorQUICTLSFingerprintFactorySelection(t *testing.T) {
	original := quic.GetClientQUICConnFactory()
	t.Cleanup(func() {
		quic.SetClientQUICConnFactory(original)
	})

	sentinel := func(*tls.Config, bool) quic.QUICConn { return nil }
	quic.SetClientQUICConnFactory(sentinel)
	sentinelFactory := quic.GetClientQUICConnFactory()
	sentinelPointer := reflect.ValueOf(sentinelFactory).Pointer()

	tests := []struct {
		name           string
		fingerprint    string
		wantFactory    bool
		wantFactorySet bool
	}{
		{
			name:        "default uses standard QUIC TLS factory",
			wantFactory: true,
		},
		{
			name:           "chrome uses uTLS factory",
			fingerprint:    "chrome",
			wantFactorySet: true,
		},
		{
			name:        "unsupported fingerprint is rejected",
			fingerprint: "firefox",
			wantFactory: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			quic.SetClientQUICConnFactory(sentinel)
			cfg := &v1.ClientCommonConfig{
				ServerAddr: "127.0.0.1",
				ServerPort: -1,
				Transport: v1.ClientTransportConfig{
					Protocol:           "quic",
					WireProtocol:       "v2",
					QUICTLSFingerprint: tc.fingerprint,
				},
			}
			require.NoError(t, cfg.Complete())

			connector := NewConnector(context.Background(), cfg)
			err := connector.Open()
			// Port -1 fails during address validation, after fingerprint
			// selection has run. This keeps the test off the network.
			require.Error(t, err)

			factoryPointer := reflect.ValueOf(quic.GetClientQUICConnFactory()).Pointer()
			if tc.wantFactory {
				require.Equal(t, sentinelPointer, factoryPointer)
			}
			if tc.wantFactorySet {
				require.NotEqual(t, sentinelPointer, factoryPointer)
			}
		})
	}
}
