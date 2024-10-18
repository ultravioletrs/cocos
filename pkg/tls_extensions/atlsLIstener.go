package atls

// #cgo LDFLAGS: -lssl -lcrypto
// #include "atls_extensions.h"
import "C"

import (
	"fmt"
	"io"
	"net"
	"os"
	"runtime/cgo"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/ultravioletrs/cocos/agent"
)

const inetAddrLen = 16

var (
	numberOfConnections = 0
	mutex               sync.Mutex
)

type GoValidationVerificationCallback func(data1, data2 []byte) int
type GoFetchAttestationCallback func(data1 []byte) []byte

func RegisterGoVVCallback(callback GoValidationVerificationCallback) uintptr {
	handle := cgo.NewHandle(callback)
	return uintptr(handle)
}

func RegisterFetchARCallback(callback GoFetchAttestationCallback) uintptr {
	handle := cgo.NewHandle(callback)
	return uintptr(handle)
}

//export callVerificationValidationCallback
func callVerificationValidationCallback(callbackHandle uintptr, attReport *C.uchar, attReportSize C.int, repData *C.uchar) C.int {
	handle := cgo.Handle(callbackHandle)
	callback := handle.Value().(GoValidationVerificationCallback)
	attestationReport := C.GoBytes(unsafe.Pointer(attReport), attReportSize)
	reportData := C.GoBytes(unsafe.Pointer(repData), agent.ReportDataSize)

	fmt.Println("Verification callback")

	return C.int(callback(attestationReport, reportData))
}

//export callFetchAttestationCallback
func callFetchAttestationCallback(callbackHandle uintptr, reportDataByte *C.uchar, outlen *C.int) *C.uchar {
	handle := cgo.Handle(callbackHandle)
	callback := handle.Value().(GoFetchAttestationCallback)
	reportData := C.GoBytes(unsafe.Pointer(reportDataByte), agent.ReportDataSize)

	fmt.Println("Fetch attestation callback")

	res := callback(reportData)

	if res == nil {
		fmt.Fprintf(os.Stderr, "attestation callback returned nill")
		return nil
	}

	*outlen = C.int(len(res))
	resultC := C.malloc(C.size_t(len(res)))
	if resultC == nil {
		fmt.Fprintf(os.Stderr, "could not allocate memory for fetch attestation callback")
		return nil
	}

	C.memcpy(resultC, unsafe.Pointer(&res[0]), C.size_t(len(res)))

	return (*C.uchar)(resultC)
}

type CustomServerListener struct {
	tlsListener *C.tls_server_connection
}

func Listen(addr string, cert []byte, key []byte, fetchAttestationHandler uintptr) (net.Listener, error) {
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

	atlsListener := C.start_tls_server(
		cCertPEM, C.int(len(cert)),
		cKeyPEM, C.int(len(key)),
		cIP, C.int(p),
		C.uintptr_t(fetchAttestationHandler))
	if atlsListener == nil {
		return nil, fmt.Errorf("could not create listener")
	}

	return &CustomServerListener{tlsListener: atlsListener}, nil
}

// accept implements the Accept method in the [Listener] interface; it
// waits for the next call and returns a generic [Conn].
func (l *CustomServerListener) Accept() (net.Conn, error) {
	conn := C.tls_server_accept(l.tlsListener)
	if conn == nil {
		return nil, fmt.Errorf("could not accept connection")
	}

	return &CustomTLSConn{tlsConn: conn, shutdown: 0}, nil
}

// close stops listening on the TCP address.
// already Accepted connections are not closed.
func (l *CustomServerListener) Close() error {
	ret := C.tls_server_close(l.tlsListener)
	if ret != 0 {
		return fmt.Errorf("could not close the TLS connection")
	}
	return nil
}

// addr returns the listener's network address, a [*TCPAddr].
// the Addr returned is shared by all invocations of Addr, so
// do not modify it.
func (l *CustomServerListener) Addr() net.Addr {
	cIP := C.tls_return_addr(&l.tlsListener.addr)
	defer C.custom_free(unsafe.Pointer(cIP))

	ip := C.GoString(cIP)

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil
	}

	port := C.tls_return_port(&l.tlsListener.addr)

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

	fmt.Println("CustomTLSConn - Read")

	if c.shutdown == 1 {
		return 0, nil
	}

	n := int(C.tls_read(c.tlsConn, unsafe.Pointer(&b[0]), C.int(len(b))))

	if n > 0 {
		return n, nil
	}

	// call the C function tls_get_error to interpret the error.
	errCode := int(C.tls_get_error(c.tlsConn, C.int(n)))

	// handle specific error codes returned by tls_get_error.
	switch errCode {
	case 0:
		return n, nil // no error.
	case -1:
		fmt.Println("Connection closed by peer")
		return 0, io.EOF // connection closed.
	case -2:
		fmt.Println("Operation incomplete, retry later")
		return 0, nil // non-fatal, just retry later.
	case -3:
		fmt.Println("I/O error")
		return 0, syscall.ECONNRESET // return connection reset error.
	default:
		fmt.Printf("SSL error occurred: %d\n", errCode)
		return 0, fmt.Errorf("SSL error")
	}
}

func (c *CustomTLSConn) Write(b []byte) (int, error) {
	c.fdWriteMutex.Lock()
	defer c.fdWriteMutex.Unlock()

	fmt.Println("CustomTLSConn - Write")

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

	fmt.Fprintf(os.Stderr, "CustomTLSConn - Close called\n")

	if c.shutdown == 1 {
		return nil
	}

	ret := C.tls_close(c.tlsConn)

	if int(ret) < 0 {
		return fmt.Errorf("TLSConn did not cose correctly")
	} else if int(ret) == 1 {
		fmt.Println("TLSConn closed correctly")
		c.tlsConn = nil
		c.shutdown = 1
	} else {
		fmt.Println("TLSConn in SHUTDOWN progress")
	}
	return nil
}

func (c *CustomTLSConn) LocalAddr() net.Addr {
	cIP := C.tls_return_addr(&c.tlsConn.local_addr)
	ipLength := C.strlen(cIP)
	defer C.custom_free(unsafe.Pointer(cIP))

	ip := C.GoStringN(cIP, C.int(ipLength))

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		fmt.Println("Invalid IP address")
		return nil
	}

	port := C.tls_return_port(&c.tlsConn.local_addr)

	fmt.Fprintf(os.Stderr, "CustomTLSConn - LocalAddr called: %s:%d\n", ip, int(port))

	return &net.TCPAddr{IP: parsedIP, Port: int(port)}
}

func (c *CustomTLSConn) RemoteAddr() net.Addr {
	cIP := C.tls_return_addr(&c.tlsConn.remote_addr)
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

	port := C.tls_return_port(&c.tlsConn.remote_addr)

	fmt.Fprintf(os.Stderr, "CustomTLSConn - RemoteAddr called: %s:%d\n", ip, int(port))

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
	if c.SetDeadline(t) != nil {
		return fmt.Errorf("could not set write deadline")
	}
	return nil
}

func (c *CustomTLSConn) SetWriteDeadline(t time.Time) error {
	if c.SetDeadline(t) != nil {
		return fmt.Errorf("could not set write deadline")
	}
	return nil
}

func DialTLSClient(hostname string, port int, vvHandle uintptr) (net.Conn, error) {
	cHostName := C.CString(hostname)
	defer C.custom_free(unsafe.Pointer(cHostName))

	conn := C.new_tls_connection(cHostName, C.int(port), C.uintptr_t(vvHandle))
	if conn == nil {
		return nil, fmt.Errorf("could not create connection")
	}

	return &CustomTLSConn{tlsConn: conn, shutdown: 0}, nil
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
