package sdk

import (
	"crypto/tls"
	"net/http"

	mfx "github.com/mainflux/mainflux/pkg/sdk/go"
)

type ContentType string

const ctJSON ContentType = "application/json"

const computationsEndpoint = "computations"

var _ SDK = (*csdk)(nil)

type SDK interface {
	// CreateComputation registers new thing and returns its id.
	CreateComputation(computation Computation, token string) (string, error)

	// ListComputations returns page of computations.
	ListComputations(token string, offset, limit uint64, name string) (ComputationsPage, error)

	// UpdateThing updates existing thing.
	UpdateComputation(computation Computation, token string) error

	//GetComputation returns computation object by id.
	GetComputation(id, token string) (Computation, error)

	// DeleteComputation removes existing computation.
	DeleteComputation(id, token string) error
}

type csdk struct {
	computationsURL string
	client          *http.Client
	mf              mfx.SDK
}

func NewSDK(URL string, mf mfx.SDK) SDK {
	return csdk{
		mf:              mf,
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

func (sdk csdk) sendRequest(req *http.Request, token string, ct ContentType) (*http.Response, error) {
	if token != "" {
		req.Header.Set("Authorization", token)
	}

	if ct != "" {
		req.Header.Add("Content-Type", string(ct))
	}

	return sdk.client.Do(req)
}
