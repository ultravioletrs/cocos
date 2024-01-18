package agentevents

import (
	"net"

	mglog "github.com/absmach/magistrala/logger"
	"github.com/mdlayher/vsock"
	"github.com/ultravioletrs/cocos/internal/events"
)

const (
	VsockEventsPort uint32 = 9998
	svc             string = "agent"
)

type service struct {
	svc      events.Service
	listener *vsock.Listener
	logger   mglog.Logger
}

func New(eventServerUrl string, logger mglog.Logger) (*service, error) {
	l, err := vsock.Listen(VsockEventsPort, nil)
	if err != nil {
		return nil, err
	}
	return &service{
		svc:      events.New(svc, eventServerUrl),
		listener: l,
		logger:   logger,
	}, nil
}

func (s *service) Foward() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			s.logger.Warn(err.Error())
			continue
		}
		go s.handleConnections(conn)
	}
}

func (s *service) handleConnections(conn net.Conn) error {
	defer conn.Close()
	b := make([]byte, 1024)
	n, err := conn.Read(b)
	if err != nil {
		return err
	}
	if err := s.svc.SendRaw(b[:n]); err != nil {
		return err
	}
	return nil
}
