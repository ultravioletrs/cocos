package grpc

// type healthRes struct {
// 	Status string `protobuf:"bytes,1,opt,name=status,proto3" json:"status,omitempty"`
// }

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
	File []byte `json:"-"`
}
