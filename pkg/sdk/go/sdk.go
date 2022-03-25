package sdk

import (
	"crypto/tls"
	"net/http"
)

const (
	// CTJSON represents JSON content type.
	CTJSON ContentType = "application/json"

	// CTJSONSenML represents JSON SenML content type.
	CTJSONSenML ContentType = "application/senml+json"

	// CTBinary represents binary content type.
	CTBinary ContentType = "application/octet-stream"
)

type ContentType string

var _ SDK = (*cSDK)(nil)

type Computation struct {
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	Datasets    []string `json:"datasets,omitempty"`
	Algorithms  []string `json:"Algorithms,omitempty"`
	// StartTime   time.Time
	// EndTime     time.Time
	Status            string   `json:"Status,omitempty"`
	Owner             string   `json:"owner,omitempty"`
	DatasetProviders  []string `json:"datasetproviders,omitempty"`
	AlorithmProviders []string `json:"alorithmproviders,omitempty"`
	// Ttl
	ID       string                 `json:"id,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

type SDK interface {
	// CreateComputation registers new thing and returns its id.
	CreateComputation(computation Computation, token string) (string, error)

	// Things returns page of things.
	Things(token string, offset, limit uint64, name string) (ThingsPage, error)

	// UpdateThing updates existing thing.
	UpdateComputation(computation Computation, token string) error
}

type cSDK struct {
	computationsURL string

	client *http.Client
}

func NewSDK(URL string) SDK {
	return &cSDK{

		computationsURL: URL,

		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
	}
}

func (sdk cSDK) sendRequest(req *http.Request, token, contentType string) (*http.Response, error) {
	if token != "" {
		req.Header.Set("Authorization", token)
	}

	if contentType != "" {
		req.Header.Add("Content-Type", contentType)
	}

	return sdk.client.Do(req)
}
