package atls

// #cgo LDFLAGS: -lssl -lcrypto
// #include "atls_extensions.h"
import "C"

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const inetAddrLen = 16

var (
	numberOfConnections = 0
	mutex               sync.Mutex
)

type CustomServerListener struct {
	tlsListener *C.tls_server_connection
}

func Listen(addr string, cert []byte, key []byte) (net.Listener, error) {
	ip, port, err := net.SplitHostPort(addr)
	fmt.Printf("IP, port is %s and %s\n", ip, addr)
	if err != nil {
		return nil, fmt.Errorf("error while creating listener: %v", err)
	}

	p, err := strconv.Atoi(port)
	if err != nil {
		return nil, fmt.Errorf("bad format of IP address: %v", err)
	}

	cCertPEM := (*C.char)(unsafe.Pointer(&cert[0]))
	cKeyPEM := (*C.char)(unsafe.Pointer(&key[0]))
	cIP := C.CString(ip)
	defer C.custom_free(unsafe.Pointer(cIP))

	fmt.Printf("IP address: %s\n", addr)

	atlsListener := C.start_tls_server(cCertPEM, C.int(len(cert)), cKeyPEM, C.int(len(key)), cIP, C.int(p))
	if atlsListener == nil {
		return nil, fmt.Errorf("could not create listener")
	}

	return &CustomServerListener{tlsListener: atlsListener}, nil
}

// Accept implements the Accept method in the [Listener] interface; it
// waits for the next call and returns a generic [Conn].
func (l *CustomServerListener) Accept() (net.Conn, error) {
	conn := C.tls_server_accept(l.tlsListener)
	if conn == nil {
		return nil, fmt.Errorf("could not accept connection")
	}

	return &CustomTLSConn{tlsConn: conn, shutdown: 0}, nil
}

// Close stops listening on the TCP address.
// Already Accepted connections are not closed.
func (l *CustomServerListener) Close() error {
	ret := C.tls_server_close(l.tlsListener)
	if ret != 0 {
		return fmt.Errorf("could not close the TLS connection")
	}
	return nil
}

// Addr returns the listener's network address, a [*TCPAddr].
// The Addr returned is shared by all invocations of Addr, so
// do not modify it.
func (l *CustomServerListener) Addr() net.Addr {
	fmt.Println("CustomServerListener Addr called")
	cIP := C.tls_server_return_ip(l.tlsListener)
	defer C.custom_free(unsafe.Pointer(cIP))

	ip := C.GoString(cIP)

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil
	}

	port := C.tls_server_return_port(l.tlsListener)

	fmt.Printf("Server IP Address: %s:%d\n", ip, int(port))

	return &net.TCPAddr{IP: parsedIP, Port: int(port)}
}

type CustomTLSConn struct {
	tlsConn      *C.tls_connection
	fdReadMutex  sync.Mutex
	fdWriteMutex sync.Mutex
	fdDelayMutex sync.Mutex
	shutdown     int
}

func (c *CustomTLSConn) Read(b []byte) (int, error) {
	c.fdReadMutex.Lock()
	defer c.fdReadMutex.Unlock()

	if c.shutdown == 1 {
		return 0, nil
	}

	n := int(C.tls_read(c.tlsConn, unsafe.Pointer(&b[0]), C.int(len(b))))

	if n > 0 {
		return n, nil
	}

	// Call the C function tls_get_error to interpret the error
	errCode := int(C.tls_get_error(c.tlsConn, C.int(n)))

	// Handle specific error codes returned by tls_get_error
	switch errCode {
	case 0:
		return n, nil // No error
	case -1:
		fmt.Println("Connection closed by peer")
		return 0, io.EOF // Connection closed
	case -2:
		fmt.Println("Operation incomplete, retry later")
		return 0, nil // Non-fatal, just retry later
	case -3:
		fmt.Println("I/O error")
		return 0, syscall.ECONNRESET // Return connection reset error
	default:
		fmt.Printf("SSL error occurred: %d\n", errCode)
		return 0, fmt.Errorf("SSL error")
	}
}

func (c *CustomTLSConn) Write(b []byte) (int, error) {
	c.fdWriteMutex.Lock()
	defer c.fdWriteMutex.Unlock()

	if c.shutdown == 1 {
		return 0, nil
	}

	n := int(C.tls_write(c.tlsConn, unsafe.Pointer(&b[0]), C.int(len(b))))
	if n < 0 {
		return 0, fmt.Errorf("could not write to TLS")
	}
	return n, nil
}

func (c *CustomTLSConn) Close() error {
	c.fdReadMutex.Lock()
	defer c.fdReadMutex.Unlock()

	c.fdWriteMutex.Lock()
	defer c.fdWriteMutex.Unlock()

	c.fdDelayMutex.Lock()
	defer c.fdDelayMutex.Unlock()

	if c.shutdown == 1 {
		return nil
	}

	ret := C.tls_close(c.tlsConn)

	if int(ret) < 0 {
		return fmt.Errorf("TLSConn did not cose corretly")
	} else if int(ret) == 1 {
		fmt.Println("TLSConn closed corretly")
		c.tlsConn = nil
		c.shutdown = 1
	}
	return nil
}

func (c *CustomTLSConn) LocalAddr() net.Addr {
	cIP := C.tls_conn_return_addr(c.tlsConn)
	ipLength := C.strlen(cIP)
	defer C.custom_free(unsafe.Pointer(cIP))

	ip := C.GoStringN(cIP, C.int(ipLength))

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		fmt.Println("Invalid IP address")
		return nil
	}

	port := C.tls_return_local_port(c.tlsConn)

	return &net.TCPAddr{IP: parsedIP, Port: int(port)}
}

func (c *CustomTLSConn) RemoteAddr() net.Addr {
	cIP := C.tls_conn_remote_addr(c.tlsConn)
	if cIP == nil {
		fmt.Println("RemoteAddr error while fetching ip")
		return nil
	}

	ipLength := C.strlen(cIP)
	defer C.custom_free(unsafe.Pointer(cIP))

	ip := C.GoStringN(cIP, C.int(ipLength))

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		fmt.Println("Invalid IP address")
		return nil
	}

	port := C.tls_return_remote_port(c.tlsConn)

	return &net.TCPAddr{IP: parsedIP, Port: int(port)}
}

func (c *CustomTLSConn) SetDeadline(t time.Time) error {
	c.fdDelayMutex.Lock()
	defer c.fdDelayMutex.Unlock()

	if c.shutdown == 1 {
		return nil
	}

	sec, usec := timeToTimeout(t)
	if C.set_socket_timeout(c.tlsConn, C.int(sec), C.int(usec)) < 0 {
		return fmt.Errorf("could not set deadline")
	}

	return nil
}

func (c *CustomTLSConn) SetReadDeadline(t time.Time) error {
	c.SetDeadline(t)
	return nil
}

func (c *CustomTLSConn) SetWriteDeadline(t time.Time) error {
	c.SetDeadline(t)
	return nil
}

func DialTLSClient(hostname string, port int) (net.Conn, error) {
	cHostName := C.CString(hostname)
	defer C.custom_free(unsafe.Pointer(cHostName))

	conn := C.new_tls_connection(cHostName, C.int(port))
	if conn == nil {
		return nil, fmt.Errorf("could not create connection")
	}

	return &CustomTLSConn{tlsConn: conn, shutdown: 0}, nil
}

func CustomDialer(ctx context.Context, addr string) (net.Conn, error) {
	fmt.Printf("CustomDialer - Addr is: %s\n", addr)
	ip, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("could not create a custom dialer")
	}

	p, err := strconv.Atoi(port)
	if err != nil {
		return nil, fmt.Errorf("bad format of IP address: %v", err)
	}

	conn, err := DialTLSClient(ip, p)
	if err != nil {
		return nil, fmt.Errorf("could not create TLS connection")
	}

	return conn, nil
}

func timeToTimeout(t time.Time) (int, int) {
	if t.IsZero() {
		return 0, 0
	}

	d := time.Until(t)
	seconds := int(d.Seconds())
	microseconds := int(d.Nanoseconds()/1000) % 1_000_000
	return seconds, microseconds
}
