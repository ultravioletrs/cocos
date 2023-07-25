package grpc

import (
	"errors"
)

// type healthReq struct{}

type runReq struct {
	Computation []byte `protobuf:"bytes,1,opt,name=algorithm,proto3" json:"algorithm,omitempty"`
}

func (req runReq) validate() error {
	if len(req.Computation) == 0 {
		return errors.New("algorithm binary is required")
	}
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

type resultReq struct {
	// No request parameters needed for retrieving computation result file
}

func (req resultReq) validate() error {
	// No request parameters to validate, so no validation logic needed
	return nil
}
