package grpc

type RunResponse struct {
	Message string `protobuf:"bytes,1,opt,name=message,proto3" json:"message,omitempty"`
}

type HealthResponse struct {
	Status string `protobuf:"bytes,1,opt,name=status,proto3" json:"status,omitempty"`
}
