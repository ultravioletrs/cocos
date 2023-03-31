package manager

import "github.com/golang/protobuf/ptypes/timestamp"

type Computation struct {
	ID                 string
	Name               string
	Description        string
	Status             string
	Owner              string
	Datasets           []string
	Algorithms         []string
	DatasetProviders   []string
	AlgorithmProviders []string
	ResultConsumers    []string
	TTL                int32
	StartTime          *timestamp.Timestamp
	EndTime            *timestamp.Timestamp
}
