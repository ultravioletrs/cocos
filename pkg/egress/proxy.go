// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package egress

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

// Proxy is an egress proxy server.
type Proxy struct {
	logger    *slog.Logger
	server    *http.Server
	addr      string
	transport *http.Transport
}

// NewProxy creates a new egress proxy.
func NewProxy(logger *slog.Logger, addr string) *Proxy {
	// Create HTTP/2 capable transport
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
		},
		ForceAttemptHTTP2: true,
	}
	// Enable HTTP/2
	if err := http2.ConfigureTransport(transport); err != nil {
		logger.Warn("Failed to configure HTTP/2 transport", "error", err)
	}

	p := &Proxy{
		logger:    logger,
		addr:      addr,
		transport: transport,
	}
	p.server = &http.Server{
		Addr:    addr,
		Handler: http.HandlerFunc(p.handle),
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
	} else if r.ProtoMajor == 2 {
		p.handleHTTP2(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	p.logger.Info("CONNECT request received", "host", host)

	// TODO: Check allowlist here

	p.logger.Debug("Dialing destination", "host", host)
	destConn, err := net.DialTimeout("tcp", host, 10*time.Second)
	if err != nil {
		p.logger.Error("Failed to dial destination", "host", host, "error", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer destConn.Close()
	p.logger.Info("Successfully connected to destination", "host", host)

	p.logger.Debug("Hijacking client connection")
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		p.logger.Error("Hijacking not supported")
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		p.logger.Error("Failed to hijack connection", "error", err)
		return
	}
	defer clientConn.Close()
	p.logger.Info("Successfully hijacked client connection", "host", host)

	// Send 200 Connection Established response
	p.logger.Debug("Sending 200 Connection Established")
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		p.logger.Error("Failed to send CONNECT response", "error", err)
		return
	}
	p.logger.Info("Starting bidirectional pipe", "host", host)

	p.pipe(clientConn, destConn)
	p.logger.Info("Pipe completed", "host", host)
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

func (p *Proxy) handleHTTP2(w http.ResponseWriter, r *http.Request) {
	p.logger.Info("HTTP/2 request", "method", r.Method, "host", r.Host, "path", r.URL.Path)

	// TODO: Check allowlist here

	// Parse the target URL from the request
	targetURL := &url.URL{
		Scheme: "http",
		Host:   r.Host,
	}

	// If the request has a full URL (absolute form), use it
	if r.URL.IsAbs() {
		targetURL = r.URL
	}

	// Create a reverse proxy with HTTP/2 transport
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = targetURL.Scheme
			req.URL.Host = targetURL.Host
			req.Host = targetURL.Host

			// Preserve the original path and query
			if !r.URL.IsAbs() {
				req.URL.Path = r.URL.Path
				req.URL.RawQuery = r.URL.RawQuery
			}

			// Remove hop-by-hop headers
			delHopHeaders(req.Header)
		},
		Transport: p.transport,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			p.logger.Error("HTTP/2 proxy error", "error", err, "host", r.Host)
			http.Error(w, err.Error(), http.StatusBadGateway)
		},
	}

	proxy.ServeHTTP(w, r)
}

func (p *Proxy) pipe(src, dst net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		n, err := io.Copy(dst, src)
		p.logger.Debug("Pipe src->dst completed", "bytes", n, "error", err)
		// Close write end of dst if possible, or just close it
		if c, ok := dst.(*net.TCPConn); ok {
			c.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		n, err := io.Copy(src, dst)
		p.logger.Debug("Pipe dst->src completed", "bytes", n, "error", err)
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
