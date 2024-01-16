package manager

import "github.com/mdlayher/vsock"

type sockService struct {
	listener *vsock.Listener
}

func NewVsock(cid int) (*sockService, error) {
	listener, err := vsock.Listen(3, nil)
	if err != nil {
		return nil, err
	}
	return &sockService{listener: listener}, nil
}

func (s *sockService) SendComputation() {}

func (s *sockService) Close() {}
