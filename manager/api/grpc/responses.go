package grpc

type healthRes struct {
	Status string `protobuf:"bytes,1,opt,name=status,proto3" json:"status,omitempty"`
}

type createDomainRes struct {
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
}

type runRes struct {
	ID string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
}
