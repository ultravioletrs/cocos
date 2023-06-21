package grpc

import (
	"errors"

	"github.com/ultravioletrs/agent/agent"
)

// type healthReq struct{}

type runReq struct {
	computation agent.Computation
}

func (req runReq) validate() error {
	return nil
}

type algoReq struct {
	Algorithm []byte `protobuf:"bytes,1,opt,name=algorithm,proto3" json:"algorithm,omitempty"`
}

func (req algoReq) validate() error {
	if len(req.Algorithm) == 0 {
		return errors.New("algorithm binary is required")
	}
	return nil
}

type dataReq struct {
	Dataset string `protobuf:"bytes,1,opt,name=dataset,proto3" json:"dataset,omitempty"`
}

func (req dataReq) validate() error {
	if len(req.Dataset) == 0 {
		return errors.New("dataset CSV file is required")
	}
	return nil
}
