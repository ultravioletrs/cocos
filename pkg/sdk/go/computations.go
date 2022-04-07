package sdk

import "time"

// Computation represents a Computation entity
type Computation struct {
	Name               string                 `json:"name,omitempty"`
	Description        string                 `json:"description,omitempty"`
	Datasets           []string               `json:"datasets,omitempty"`
	Algorithms         []string               `json:"algorithms,omitempty"`
	StartTime          time.Time              `json:"start_time,omitempty"`
	EndTime            time.Time              `json:"end_time,omitempty"`
	Status             string                 `json:"status,omitempty"`
	Owner              string                 `json:"owner,omitempty"`
	DatasetProviders   []string               `json:"dataset_providers,omitempty"`
	AlgorithmProviders []string               `json:"algorithm_providers,omitempty"`
	ID                 string                 `json:"id,omitempty"`
	Metadata           map[string]interface{} `json:"metadata,omitempty"`
}

type ComputationsPage struct {
	Computation []Computation `json:"computations"`
	pageRes
}
