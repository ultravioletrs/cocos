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
	attest "github.com/ultravioletrs/cocos/pkg/attestation"
)

const (
	NoTee int = iota
	AmdSevSnp
)

const (
	NO_ERROR          = 0
	ERROR_ZERO_RETURN = 6
	ERROR_WANT_READ   = 2
	ERROR_WANT_WRITE  = 3
	ERROR_SYSCALL     = 5
	ERROR_SSL         = 1
)

type ValidationVerification func(data1, data2 []byte) int
type FetchAttestation func(data1 []byte) []byte

func registerFetchAttestation(callback FetchAttestation) uintptr {
	handle := cgo.NewHandle(callback)
	return uintptr(handle)
}

func registerValidationVerification(callback ValidationVerification) uintptr {
	handle := cgo.NewHandle(callback)
	return uintptr(handle)
}

//export validationVerificationCallback
func validationVerificationCallback(teeType C.int) uintptr {
	switch int(teeType) {
	case NoTee:
		return uintptr(0)
	case AmdSevSnp:
		return registerValidationVerification(attest.VerifyAttestationReportTLS)
	default:
		return uintptr(0)
	}
}

//export fetchAttestationCallback
func fetchAttestationCallback(teeType C.int) uintptr {
	switch int(teeType) {
	case NoTee:
		return uintptr(0)
	case AmdSevSnp:
		return registerFetchAttestation(attest.FetchAttestation)
	default:
		return uintptr(0)
	}
}

//export callVerificationValidationCallback
func callVerificationValidationCallback(callbackHandle uintptr, attReport *C.uchar, attReportSize C.int, repData *C.uchar) C.int {
	handle := cgo.Handle(callbackHandle)
	defer handle.Delete()

	callback := handle.Value().(ValidationVerification)
	attestationReport := C.GoBytes(unsafe.Pointer(attReport), attReportSize)
	reportData := C.GoBytes(unsafe.Pointer(repData), agent.ReportDataSize)

	return C.int(callback(attestationReport, reportData))
}

//export callFetchAttestationCallback
func callFetchAttestationCallback(callbackHandle uintptr, reportDataByte *C.uchar, outlen *C.int) *C.uchar {
	handle := cgo.Handle(callbackHandle)
	defer handle.Delete()

	callback := handle.Value().(FetchAttestation)
	reportData := C.GoBytes(unsafe.Pointer(reportDataByte), agent.ReportDataSize)

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

type ATLSServerListener struct {
	tlsListener *C.tls_server_connection
}

func Listen(addr string, cert []byte, key []byte) (net.Listener, error) {
	ip, port, err := net.SplitHostPort(addr)
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
	defer C.free(unsafe.Pointer(cIP))

	atlsListener := C.start_tls_server(
		cCertPEM, C.int(len(cert)),
		cKeyPEM, C.int(len(key)),
		cIP, C.int(p))
	if atlsListener == nil {
		return nil, fmt.Errorf("could not create listener")
	}

	return &ATLSServerListener{tlsListener: atlsListener}, nil
}

// accept implements the Accept method in the [Listener] interface; it
// waits for the next call and returns a generic [Conn].
func (l *ATLSServerListener) Accept() (net.Conn, error) {
	conn := C.tls_server_accept(l.tlsListener)
	if conn == nil {
		return &ATLSConn{tlsConn: nil}, nil
	}

	return &ATLSConn{tlsConn: conn}, nil
}

// close stops listening on the TCP address.
// already Accepted connections are not closed.
func (l *ATLSServerListener) Close() error {
	ret := C.tls_server_close(l.tlsListener)
	if ret != 0 {
		return fmt.Errorf("could not close the TLS connection")
	}
	return nil
}

// addr returns the listener's network address, a [*TCPAddr].
// the Addr returned is shared by all invocations of Addr, so
// do not modify it.
func (l *ATLSServerListener) Addr() net.Addr {
	cIP := C.tls_return_addr(&l.tlsListener.addr)
	defer C.free(unsafe.Pointer(cIP))

	ip := C.GoString(cIP)

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil
	}

	port := C.tls_return_port(&l.tlsListener.addr)

	return &net.TCPAddr{IP: parsedIP, Port: int(port)}
}

type ATLSConn struct {
	tlsConn      *C.tls_connection
	fdReadMutex  sync.Mutex
	fdWriteMutex sync.Mutex
	fdDelayMutex sync.Mutex
}

func (c *ATLSConn) Read(b []byte) (int, error) {
	c.fdReadMutex.Lock()
	defer c.fdReadMutex.Unlock()

	if c.tlsConn == nil {
		return 0, fmt.Errorf("tls connection is NULL")
	}

	n := int(C.tls_read(c.tlsConn, unsafe.Pointer(&b[0]), C.int(len(b))))

	if n > 0 {
		return n, nil
	}

	// call the C function SSL_get_error to interpret the error.
	errCode := int(C.SSL_get_error(c.tlsConn.ssl, C.int(n)))

	// handle specific error codes returned by SSL_get_error.
	switch errCode {
	case NO_ERROR:
		return n, nil // no error.
	case ERROR_ZERO_RETURN:
		fmt.Fprintf(os.Stderr, "Connection closed by peer")
		return 0, io.EOF // connection closed.
	case ERROR_WANT_READ:
		fmt.Fprintf(os.Stderr, "Operation read incomplete, retry later")
		return 0, nil // non-fatal, just retry later.
	case ERROR_WANT_WRITE:
		fmt.Fprintf(os.Stderr, "Operation write incomplete, retry later")
		return 0, nil // non-fatal, just retry later.
	case ERROR_SYSCALL:
		fmt.Fprintf(os.Stderr, "I/O error")
		return 0, syscall.ECONNRESET // return connection reset error.
	case ERROR_SSL:
		fmt.Fprintf(os.Stderr, "I/O error")
		return 0, syscall.ECONNRESET // return connection reset error.
	default:
		fmt.Fprintf(os.Stderr, "SSL error occurred: %d\n", errCode)
		return 0, fmt.Errorf("SSL error")
	}
}

func (c *ATLSConn) Write(b []byte) (int, error) {
	c.fdWriteMutex.Lock()
	defer c.fdWriteMutex.Unlock()

	if c.tlsConn == nil {
		return 0, fmt.Errorf("tls connection is NULL")
	}

	n := int(C.tls_write(c.tlsConn, unsafe.Pointer(&b[0]), C.int(len(b))))
	if n < 0 {
		return 0, fmt.Errorf("could not write to TLS")
	}
	return n, nil
}

func (c *ATLSConn) Close() error {
	c.fdReadMutex.Lock()
	defer c.fdReadMutex.Unlock()

	c.fdWriteMutex.Lock()
	defer c.fdWriteMutex.Unlock()

	c.fdDelayMutex.Lock()
	defer c.fdDelayMutex.Unlock()

	if c.tlsConn == nil {
		return nil
	}

	ret := C.tls_close(c.tlsConn)

	if int(ret) < 0 {
		c.tlsConn = nil
		return fmt.Errorf("TLSConn did not close correctly")
	} else if int(ret) == 1 {
		c.tlsConn = nil
	}

	return nil
}

func (c *ATLSConn) LocalAddr() net.Addr {
	if c.tlsConn == nil {
		return nil
	}
	cIP := C.tls_return_addr(&c.tlsConn.local_addr)
	ipLength := C.strlen(cIP)
	defer C.free(unsafe.Pointer(cIP))

	ip := C.GoStringN(cIP, C.int(ipLength))

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		fmt.Println("Invalid IP address")
		return nil
	}

	port := C.tls_return_port(&c.tlsConn.local_addr)

	return &net.TCPAddr{IP: parsedIP, Port: int(port)}
}

func (c *ATLSConn) RemoteAddr() net.Addr {
	if c.tlsConn == nil {
		return nil
	}
	cIP := C.tls_return_addr(&c.tlsConn.remote_addr)
	if cIP == nil {
		fmt.Println("RemoteAddr error while fetching ip")
		return nil
	}

	ipLength := C.strlen(cIP)
	defer C.free(unsafe.Pointer(cIP))

	ip := C.GoStringN(cIP, C.int(ipLength))

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		fmt.Println("Invalid IP address")
		return nil
	}

	port := C.tls_return_port(&c.tlsConn.remote_addr)

	return &net.TCPAddr{IP: parsedIP, Port: int(port)}
}

func (c *ATLSConn) SetDeadline(t time.Time) error {
	c.fdDelayMutex.Lock()
	defer c.fdDelayMutex.Unlock()

	if c.tlsConn == nil {
		return nil
	}

	sec, usec := timeToTimeout(t)
	if C.set_socket_read_timeout(c.tlsConn, C.int(sec), C.int(usec)) < 0 {
		return fmt.Errorf("could not set read deadline, socket timeout failed")
	}

	if C.set_socket_write_timeout(c.tlsConn, C.int(sec), C.int(usec)) < 0 {
		return fmt.Errorf("could not set write deadline, socket timeout failed")
	}

	return nil
}

func (c *ATLSConn) SetReadDeadline(t time.Time) error {
	c.fdDelayMutex.Lock()
	defer c.fdDelayMutex.Unlock()

	if c.tlsConn == nil {
		return nil
	}

	sec, usec := timeToTimeout(t)
	if C.set_socket_read_timeout(c.tlsConn, C.int(sec), C.int(usec)) < 0 {
		return fmt.Errorf("could not set read deadline, socket timeout failed")
	}

	return nil
}

func (c *ATLSConn) SetWriteDeadline(t time.Time) error {
	c.fdDelayMutex.Lock()
	defer c.fdDelayMutex.Unlock()

	if c.tlsConn == nil {
		return nil
	}

	sec, usec := timeToTimeout(t)
	if C.set_socket_write_timeout(c.tlsConn, C.int(sec), C.int(usec)) < 0 {
		return fmt.Errorf("could not set write deadline, socket timeout failed")
	}

	return nil
}

func DialTLSClient(hostname string, port int) (net.Conn, error) {
	cHostName := C.CString(hostname)
	defer C.free(unsafe.Pointer(cHostName))

	conn := C.new_tls_connection(cHostName, C.int(port))
	if conn == nil {
		return nil, fmt.Errorf("could not create connection")
	}

	return &ATLSConn{tlsConn: conn}, nil
}

func timeToTimeout(t time.Time) (int, int) {
	if t.IsZero() {
		return 0, 0
	}

	d := time.Until(t)
	if d <= 0 {
		return 0, 0
	}

	seconds := int(d.Seconds())
	microseconds := int(d.Nanoseconds()/1000) % 1_000_000
	return seconds, microseconds
}
