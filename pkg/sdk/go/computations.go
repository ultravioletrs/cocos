package sdk

import "time"

type Computation struct {
	Name              string   `json:"name,omitempty"`
	Description       string   `json:"description,omitempty"`
	Datasets          []string `json:"datasets,omitempty"`
	Algorithms        []string `json:"Algorithms,omitempty"`
	StartTime         time.Time
	EndTime           time.Time
	Status            string   `json:"Status,omitempty"`
	Owner             string   `json:"owner,omitempty"`
	DatasetProviders  []string `json:"datasetproviders,omitempty"`
	AlorithmProviders []string `json:"alorithmproviders,omitempty"`
	// Ttl
	ID       string                 `json:"id,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

type ComputationsPage struct {
	Computation []Computation `json:"computations"`
	pageRes
}
