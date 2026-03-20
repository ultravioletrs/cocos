// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package ingress

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sync"

	"github.com/ultravioletrs/cocos/pkg/atls"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// ProxyConfig contains configuration for starting a proxy instance.
type ProxyConfig struct {
	Port         string
	CertFile     string
	KeyFile      string
	ServerCAFile string
	ClientCAFile string
	AttestedTLS  bool
}

// ProxyContext provides context information for logging and tracking.
type ProxyContext struct {
	ID   string
	Name string
}

// ProxyServer manages ingress proxy instances.
type ProxyServer interface {
	Start(cfg ProxyConfig, ctx ProxyContext) error
	Stop() error
}

type proxyServer struct {
	mu           sync.RWMutex
	logger       *slog.Logger
	backendURL   *url.URL
	certProvider atls.CertificateProvider
	httpServer   *http.Server
	started      bool
	stopped      bool
}

// NewProxyServer creates a new ingress proxy server manager.
func NewProxyServer(logger *slog.Logger, backendURL *url.URL, certProvider atls.CertificateProvider) ProxyServer {
	return &proxyServer{
		logger:       logger,
		backendURL:   backendURL,
		certProvider: certProvider,
	}
}

// Start starts the proxy server with the given configuration.
func (p *proxyServer) Start(cfg ProxyConfig, ctx ProxyContext) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.started {
		return fmt.Errorf("proxy server already started")
	}
	if p.stopped {
		return fmt.Errorf("proxy server already stopped")
	}

	if cfg.Port == "" {
		cfg.Port = "7002"
	}

	addr := fmt.Sprintf("0.0.0.0:%s", cfg.Port)

	// Configure Reverse Proxy
	var rp *httputil.ReverseProxy

	// Check if backend is Unix socket or TCP
	if p.backendURL.Scheme == "unix" {
		// For Unix socket backend, we need to manually configure the reverse proxy
		// because NewSingleHostReverseProxy doesn't support unix:// scheme
		targetURL := &url.URL{
			Scheme: "http",
			Host:   "unix",
		}
		rp = httputil.NewSingleHostReverseProxy(targetURL)

		// Override the Director to not modify the request
		originalDirector := rp.Director
		rp.Director = func(req *http.Request) {
			originalDirector(req)
			// Set the URL to point to the backend service
			req.URL.Scheme = "http"
			req.URL.Host = "unix"
		}

		// Configure Transport for Unix socket with HTTP/2
		rp.Transport = &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				var d net.Dialer
				// Use Unix socket path from URL
				return d.DialContext(ctx, "unix", p.backendURL.Path)
			},
		}
	} else {
		// TCP backend
		rp = httputil.NewSingleHostReverseProxy(p.backendURL)
		rp.Transport = &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			},
		}
	}

	// Wrap handler with h2c for HTTP/2 cleartext support (required for gRPC without TLS)
	h2cHandler := h2c.NewHandler(rp, &http2.Server{})

	p.httpServer = &http.Server{
		Addr:    addr,
		Handler: h2cHandler,
	}

	// Configure TLS
	var tlsConfig *tls.Config
	var err error
	contextDesc := fmt.Sprintf("context %s", ctx.ID)
	if ctx.Name != "" {
		contextDesc = fmt.Sprintf("%s (%s)", ctx.Name, ctx.ID)
	}

	if cfg.AttestedTLS {
		if p.certProvider == nil {
			return fmt.Errorf("attested TLS requested for ingress proxy but no certificate provider available. Please ensure a CC platform is detected (not NoCC), aTLS is enabled, and the attestation service is running")
		}
		tlsConfig = &tls.Config{
			GetCertificate: p.certProvider.GetCertificate,
			ClientAuth:     tls.NoClientCert,
			NextProtos:     []string{"h2", "http/1.1"},
		}

		mtls, err := ConfigureCertificateAuthorities(tlsConfig, cfg.ServerCAFile, cfg.ClientCAFile)
		if err != nil {
			return fmt.Errorf("failed to setup attested TLS: %w", err)
		}
		tlsConfig.NextProtos = []string{"h2", "http/1.1"}

		if mtls {
			p.logger.Info(fmt.Sprintf("ingress-proxy listening at %s with Attested mTLS for %s", addr, contextDesc))
		} else {
			p.logger.Info(fmt.Sprintf("ingress-proxy listening at %s with Attested TLS for %s", addr, contextDesc))
		}

		p.started = true
		go func() {
			listener, listenErr := p.attestedListener(addr, tlsConfig, identity)
			if listenErr != nil {
				p.logger.Error(fmt.Sprintf("failed to listen: %s", listenErr))
				return
			}

			serveErr := p.httpServer.Serve(listener)
			if serveErr != nil && serveErr != http.ErrServerClosed {
				p.logger.Error(fmt.Sprintf("ingress-proxy server error: %s", serveErr))
			}
		}()
		return nil
	} else if cfg.CertFile != "" && cfg.KeyFile != "" {
		// Regular TLS
		tlsSetup, err := SetupRegularTLS(cfg.CertFile, cfg.KeyFile, cfg.ServerCAFile, cfg.ClientCAFile)
		if err != nil {
			return fmt.Errorf("failed to setup TLS: %w", err)
		}
		tlsConfig = tlsSetup.Config
		tlsConfig.NextProtos = []string{"h2", "http/1.1"}

		if tlsSetup.MTLS {
			p.logger.Info(fmt.Sprintf("ingress-proxy listening at %s with mTLS for %s", addr, contextDesc))
		} else {
			p.logger.Info(fmt.Sprintf("ingress-proxy listening at %s with TLS for %s", addr, contextDesc))
		}
	} else {
		p.logger.Info(fmt.Sprintf("ingress-proxy listening at %s without TLS for %s", addr, contextDesc))
	}

	p.started = true

	// Start server in goroutine
	go func() {
		var err error
		if tlsConfig != nil {
			ln, listenErr := net.Listen("tcp", addr)
			if listenErr != nil {
				p.logger.Error(fmt.Sprintf("failed to listen: %s", listenErr))
				return
			}
			tlsLn := tls.NewListener(ln, tlsConfig)
			err = p.httpServer.Serve(tlsLn)
		} else {
			err = p.httpServer.ListenAndServe()
		}

		if err != nil && err != http.ErrServerClosed {
			p.logger.Error(fmt.Sprintf("ingress-proxy server error: %s", err))
		}
	}()

	return nil
}

func (p *proxyServer) attestedListener(addr string, tlsConfig *tls.Config, identity tls.Certificate) (net.Listener, error) {
	network := "tcp"
	address := addr
	if len(addr) > 0 && addr[0] == '/' {
		network = "unix"
		address = addr
		_ = os.Remove(address)
	}

	return atls.Listen(network, address, &atls.ServerConfig{
		TLSConfig:           tlsConfig,
		Identity:            identity,
		BuildLeafExtensions: p.certProvider.BuildLeafExtensions,
	})
}

// Stop stops the proxy server.
func (p *proxyServer) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.stopped {
		return nil
	}
	p.stopped = true

	if p.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*1000000000) // 5 seconds
		defer cancel()
		if err := p.httpServer.Shutdown(ctx); err != nil {
			return fmt.Errorf("failed to shutdown server: %w", err)
		}
		p.logger.Info("ingress-proxy stopped")
	}

	return nil
}
