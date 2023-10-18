package grpc

type runRes struct {
	Computation string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
}

type algoRes struct {
	AlgorithmID string `json:"algorithmId,omitempty"`
}

type dataRes struct {
	DatasetID string `json:"datasetId,omitempty"`
}

type resultRes struct {
	File []byte `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
}
