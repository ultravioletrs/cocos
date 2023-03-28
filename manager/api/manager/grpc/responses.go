package grpc

type runRes struct {
	Message string `protobuf:"bytes,1,opt,name=message,proto3" json:"message,omitempty"`
}

type healthRes struct {
	Status string `protobuf:"bytes,1,opt,name=status,proto3" json:"status,omitempty"`
}

type createDomainRes struct {
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
}
