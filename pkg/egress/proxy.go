// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package egress

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

// Proxy is an egress proxy server.
type Proxy struct {
	logger *slog.Logger
	server *http.Server
	addr   string
}

// NewProxy creates a new egress proxy.
func NewProxy(logger *slog.Logger, addr string) *Proxy {
	p := &Proxy{
		logger: logger,
		addr:   addr,
	}
	p.server = &http.Server{
		Addr:    addr,
		Handler: http.HandlerFunc(p.handle),
		// Disable HTTP/2 for now to simplify CONNECT handling if needed,
		// though net/http handles it well.
	}
	return p
}

// Start starts the proxy server.
func (p *Proxy) Start() error {
	p.logger.Info("Starting egress proxy", "addr", p.addr)
	return p.server.ListenAndServe()
}

// Stop stops the proxy server.
func (p *Proxy) Stop(ctx context.Context) error {
	p.logger.Info("Stopping egress proxy")
	return p.server.Shutdown(ctx)
}

func (p *Proxy) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	p.logger.Info("Connect request", "host", host)

	// TODO: Check allowlist here

	destConn, err := net.DialTimeout("tcp", host, 10*time.Second)
	if err != nil {
		p.logger.Error("Failed to dial destination", "host", host, "error", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer destConn.Close()

	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		p.logger.Error("Hijacking not supported")
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		p.logger.Error("Failed to hijack connection", "error", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	p.pipe(clientConn, destConn)
}

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	p.logger.Info("HTTP request", "method", r.Method, "url", r.URL.String())

	// TODO: Check allowlist here

	r.RequestURI = "" // RequestURI must be empty for Client.Do

	// Remove hop-by-hop headers
	delHopHeaders(r.Header)

	// Create a client to send the request
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(r)
	if err != nil {
		p.logger.Error("Failed to execute request", "error", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy headers
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (p *Proxy) pipe(src, dst net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(dst, src)
		// Close write end of dst if possible, or just close it
		if c, ok := dst.(*net.TCPConn); ok {
			c.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(src, dst)
		if c, ok := src.(*net.TCPConn); ok {
			c.CloseWrite()
		}
	}()

	wg.Wait()
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func delHopHeaders(header http.Header) {
	// Standard hop-by-hop headers
	hopHeaders := []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailers",
		"Transfer-Encoding",
		"Upgrade",
	}
	for _, h := range hopHeaders {
		header.Del(h)
	}
}
