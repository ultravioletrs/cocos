package grpc

import (
	"github.com/ultravioletrs/agent/agent"
)

// type healthReq struct{}

type runReq struct {
	computation agent.Computation
}

func (req runReq) validate() error {
	return nil
}
