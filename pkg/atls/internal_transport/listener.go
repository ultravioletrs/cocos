// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package internaltransport

import (
	"crypto/tls"
	"fmt"
	"net"
)

type Listener struct {
	raw net.Listener
	cfg *ServerConfig
}

func Listen(network, address string, cfg *ServerConfig) (*Listener, error) {
	if cfg == nil || cfg.TLSConfig == nil {
		return nil, fmt.Errorf("atls: missing server TLS config")
	}
	raw, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}
	return &Listener{raw: raw, cfg: cfg}, nil
}

func (l *Listener) Accept() (net.Conn, error) {
	rawConn, err := l.raw.Accept()
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Server(rawConn, l.cfg.TLSConfig.Clone())
	conn, err := Server(tlsConn, l.cfg)
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}

	return conn, nil
}

func (l *Listener) Close() error {
	return l.raw.Close()
}

func (l *Listener) Addr() net.Addr {
	return l.raw.Addr()
}
