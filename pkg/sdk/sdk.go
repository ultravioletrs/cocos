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
	Ping(string) (string, error)
	Run(computation Computation) (string, error)
	Algo(algorithm []byte) (string, error)
	Data(dataset string) (string, error)
	Result() ([]byte, error)
}

type agentSDK struct {
	agentURL string
	client   *http.Client
}

type Config struct {
	agentURL string
}

// NewSDK creates a new CoCoS SDK instance.
func NewSDK(conf Config) SDK {
	return agentSDK{
		agentURL: conf.agentURL,
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
	}
}

func (sdk agentSDK) sendRequest(req *http.Request, token string, ct ContentType) (*http.Response, error) {
	if token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	if ct != "" {
		req.Header.Add("Content-Type", string(ct))
	}

	return sdk.client.Do(req)
}
