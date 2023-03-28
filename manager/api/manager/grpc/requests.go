package grpc

import (
	"github.com/ultravioletrs/manager/manager"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type healthReq struct{}

type runReq struct {
	Name               string                 `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	Description        string                 `protobuf:"bytes,3,opt,name=description,proto3" json:"description,omitempty"`
	Status             string                 `protobuf:"bytes,4,opt,name=status,proto3" json:"status,omitempty"`
	Owner              string                 `protobuf:"bytes,5,opt,name=owner,proto3" json:"owner,omitempty"`
	StartTime          *timestamppb.Timestamp `protobuf:"bytes,6,opt,name=start_time,json=startTime,proto3" json:"start_time,omitempty"`
	EndTime            *timestamppb.Timestamp `protobuf:"bytes,7,opt,name=end_time,json=endTime,proto3" json:"end_time,omitempty"`
	Datasets           []string               `protobuf:"bytes,8,rep,name=datasets,proto3" json:"datasets,omitempty"`
	Algorithms         []string               `protobuf:"bytes,9,rep,name=algorithms,proto3" json:"algorithms,omitempty"`
	DatasetProviders   []string               `protobuf:"bytes,10,rep,name=dataset_providers,json=datasetProviders,proto3" json:"dataset_providers,omitempty"`
	AlgorithmProviders []string               `protobuf:"bytes,11,rep,name=algorithm_providers,json=algorithmProviders,proto3" json:"algorithm_providers,omitempty"`
	Ttl                int32                  `protobuf:"varint,12,opt,name=ttl,proto3" json:"ttl,omitempty"`
	ResultConsumers    []string               `protobuf:"bytes,13,rep,name=result_consumers,json=resultConsumers,proto3" json:"result_consumers,omitempty"`
}

type createDomainReq struct {
	Pool   string `protobuf:"bytes,1,opt,name=pool,proto3" json:"pool,omitempty"`
	Volume string `protobuf:"bytes,2,opt,name=volume,proto3" json:"volume,omitempty"`
	Domain string `protobuf:"bytes,3,opt,name=domain,proto3" json:"domain,omitempty"`
}

func (req createDomainReq) validate() error {
	if req.Pool == "" {
		return manager.ErrMalformedEntity
	}
	if req.Volume == "" {
		return manager.ErrMalformedEntity
	}
	if req.Domain == "" {
		return manager.ErrMalformedEntity
	}
	return nil
}
