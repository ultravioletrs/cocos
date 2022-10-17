package sdk

import (
	"crypto/tls"
	"net/http"
)

type ContentType string

const ctJSON ContentType = "application/json"

var _ SDK = (*csdk)(nil)

type SDK interface {
	// CreateComputation registers new computation and returns its id.
	CreateComputation(computation Computation, token string) (string, error)

	// ListComputations returns page of computations.
	ListComputations(token string, offset, limit uint64, name string) (ComputationsPage, error)

	// UpdateComputation updates existing computation.
	UpdateComputation(computation Computation, token string) error

	//GetComputation returns computation object by id.
	GetComputation(id, token string) (Computation, error)

	// DeleteComputation removes existing computation.
	DeleteComputation(id, token string) error

	// CreateDataset registers new dataset and returns its id.
	CreateDataset(dataset Dataset, token string) (string, error)

	// ListDatasets returns page of datasets.
	ListDatasets(token string, offset, limit uint64, name string) (DatasetsPage, error)

	// UpdateDataset updates existing dataset.
	UpdateDataset(dataset Dataset, token string) error

	//GetDataset returns dataset object by id.
	Dataset(id, token string) (Dataset, error)

	// DeleteDataaset removes existing dataset.
	DeleteDataset(id, token string) error
}

type csdk struct {
	datasetsURL     string
	computationsURL string
	client          *http.Client
}

// Config represents the SDK configuration.
type Config struct {
	DatasetsURL     string
	ComputationsURL string
}

// NewSDK creates a new CoCoS SDK instance.
func NewSDK(conf Config) SDK {
	return csdk{
		computationsURL: conf.ComputationsURL,
		datasetsURL:     conf.DatasetsURL,
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
	}
}

func (sdk csdk) sendRequest(req *http.Request, token string, ct ContentType) (*http.Response, error) {
	if token != "" {
		req.Header.Set("Authorization", token)
	}

	if ct != "" {
		req.Header.Add("Content-Type", string(ct))
	}

	return sdk.client.Do(req)
}
