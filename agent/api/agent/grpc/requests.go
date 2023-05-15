package grpc

import (
	"github.com/ultravioletrs/agent/agent"
)

// type healthReq struct{}

type runReq struct {
	Name               string   `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Description        string   `protobuf:"bytes,2,opt,name=description,proto3" json:"description,omitempty"`
	Owner              string   `protobuf:"bytes,3,opt,name=owner,proto3" json:"owner,omitempty"`
	Datasets           []string `protobuf:"bytes,4,rep,name=datasets,proto3" json:"datasets,omitempty"`
	Algorithms         []string `protobuf:"bytes,5,rep,name=algorithms,proto3" json:"algorithms,omitempty"`
	DatasetProviders   []string `protobuf:"bytes,6,rep,name=dataset_providers,json=datasetProviders,proto3" json:"dataset_providers,omitempty"`
	AlgorithmProviders []string `protobuf:"bytes,7,rep,name=algorithm_providers,json=algorithmProviders,proto3" json:"algorithm_providers,omitempty"`
	ResultConsumers    []string `protobuf:"bytes,8,rep,name=result_consumers,json=resultConsumers,proto3" json:"result_consumers,omitempty"`
	TTL                int32    `protobuf:"varint,9,opt,name=ttl,proto3" json:"ttl,omitempty"`
}

func (req runReq) validate() error {
	if req.Name == "" {
		return agent.ErrMalformedEntity
	}
	if req.Owner == "" {
		return agent.ErrMalformedEntity
	}
	if len(req.Datasets) == 0 {
		return agent.ErrMalformedEntity
	}
	if len(req.Algorithms) == 0 {
		return agent.ErrMalformedEntity
	}
	if req.TTL <= 0 {
		return agent.ErrMalformedEntity
	}
	return nil
}
