package grpc

import (
	"github.com/ultravioletrs/manager/manager"
)

type healthReq struct{}

type createDomainReq struct {
	Pool   string `protobuf:"bytes,1,opt,name=pool,proto3" json:"pool,omitempty"`
	Volume string `protobuf:"bytes,2,opt,name=volume,proto3" json:"volume,omitempty"`
	Domain string `protobuf:"bytes,3,opt,name=domain,proto3" json:"domain,omitempty"`
}

func (req createDomainReq) validate() error {
	// if req.Pool == "" {
	// 	return manager.ErrMalformedEntity
	// }
	// if req.Volume == "" {
	// 	return manager.ErrMalformedEntity
	// }
	// if req.Domain == "" {
	// 	return manager.ErrMalformedEntity
	// }
	return nil
}

type runReq struct {
	Computation []byte `json:"computation,omitempty"`
}

func (req runReq) validate() error {
	if len(req.Computation) == 0 {
		return manager.ErrMalformedEntity
	}
	return nil
}
