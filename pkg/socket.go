package socket

import (
	"fmt"
	"io"
	"net"
	"os"
)

func StartUnixSocketServer(socketPath string) (net.Listener, error) {
	// Remove any existing socket file
	_ = os.Remove(socketPath)

	// Create a Unix domain socket listener
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("error creating socket listener: %v", err)
	}

	fmt.Println("Unix domain socket server is listening on", socketPath)

	return listener, nil
}

func AcceptConnection(listener net.Listener, dataChannel chan []byte, errorChannel chan error) {
	conn, err := listener.Accept()
	if err != nil {
		errorChannel <- fmt.Errorf("error accepting connection:: %v", err)
	}

	handleConnection(conn, dataChannel, errorChannel)
}

func handleConnection(conn net.Conn, dataChannel chan []byte, errorChannel chan error) {
	defer conn.Close()

	// Create a dynamic buffer to store incoming data
	var buffer []byte
	tmp := make([]byte, 1024)

	for {
		// Read data into the temporary buffer
		n, err := conn.Read(tmp)
		if err != nil {
			if err == io.EOF {
				break
			}
			errorChannel <- err
		}
		buffer = append(buffer, tmp[:n]...)
	}

	dataChannel <- buffer
}
