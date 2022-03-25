package sdk

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
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
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

type SDK interface {
	// CreateComputation registers new thing and returns its id.
	CreateComputation(computation Computation, token string) (string, error)

	// Computations returns page of computations.
	Computations(token string, offset, limit uint64, name string) (ComputationsPage, error)
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

const computationsEndpoint = "computations"
const connectEndpoint = "connect"

func (sdk cSDK) CreateComputation(c Computation, token string) (string, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("%s/%s", sdk.computationsURL, computationsEndpoint)

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return "", err
	}

	resp, err := sdk.sendRequest(req, token, string(CTJSON))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return "", errors.New("Fail to create")
	}

	id := strings.TrimPrefix(resp.Header.Get("Location"), fmt.Sprintf("/%s/", computationsEndpoint))
	return id, nil
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
