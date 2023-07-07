package sdk

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
)

type ContentType string

const ctJSON ContentType = "application/json"

var _ SDK = (*agentSDK)(nil)

var (
	// ErrAuthorization indicates failure occurred while authorizing the entity.
	ErrAuthorization = errors.New("failed to perform authorization over the entity")
	//ErrFailedComputation indicates that computation run failed.
	ErrFailedComputation = errors.New("failed to run computation")
	//ErrMalformedEntity
	ErrMalformedEntity = errors.New("malformed entity specification")
)

type SDK interface {
	// Ping sends a GET request to the specified URL and returns the response as a string.
	Ping(url string) (string, error)

	// Run sends a POST request with the provided computation and returns the response as a string.
	Run(computation Computation) (string, error)

	// UploadAlgorithm sends a POST request with the provided algorithm as bytes and returns the response as a string.
	UploadAlgorithm(algorithm []byte) (string, error)

	// UploadDataset sends a POST request with the provided dataset and returns the response as a string.
	UploadDataset(dataset string) (string, error)

	// Result sends a GET request to retrieve the computation result and returns the computation result file as a byte slice.
	Result() ([]byte, error)
}

type agentSDK struct {
	agentURL string
	client   *http.Client
}

type Config struct {
	AgentURL string
}

func NewSDK(conf Config) SDK {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{},
	}

	client := &http.Client{
		Transport: transport,
	}

	return &agentSDK{
		agentURL: conf.AgentURL,
		client:   client,
	}
}

func (sdk *agentSDK) sendRequest(req *http.Request, token string, ct ContentType) (*http.Response, error) {
	if token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	if ct != "" {
		req.Header.Add("Content-Type", string(ct))
	}

	return sdk.client.Do(req)
}
