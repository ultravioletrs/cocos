package sdk

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	mfx "github.com/mainflux/mainflux/pkg/sdk/go"
)

const computationsEndpoint = "computations"

// CTJSON represents JSON content type.
const CTJSON ContentType = "application/json"

type ContentType string

var _ SDK = (*cSDK)(nil)

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

	CreateUser(username, password string) (string, error)
}

type cSDK struct {
	computationsURL string
	client          *http.Client
	mf              mfx.SDK
}

func NewSDK(URL string, mf mfx.SDK) SDK {
	return &cSDK{
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
		return "", errors.New("failed to create entity")
	}

	id := strings.TrimPrefix(resp.Header.Get("Location"), fmt.Sprintf("/%s/", computationsEndpoint))
	return id, nil
}

func (sdk cSDK) ListComputations(token string, offset, limit uint64, name string) (ComputationsPage, error) {
	endpoint := fmt.Sprintf("%s?offset=%d&limit=%d&name=%s", computationsEndpoint, offset, limit, name)
	url := fmt.Sprintf("%s/%s", sdk.computationsURL, endpoint)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return ComputationsPage{}, err
	}

	resp, err := sdk.sendRequest(req, token, string(CTJSON))
	if err != nil {
		return ComputationsPage{}, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ComputationsPage{}, err
	}

	if resp.StatusCode != http.StatusOK {
		return ComputationsPage{}, errors.New("failed to list computations")
	}

	var tp ComputationsPage
	if err := json.Unmarshal(body, &tp); err != nil {
		return ComputationsPage{}, err
	}

	return tp, nil
}

func (sdk cSDK) GetComputation(id, token string) (Computation, error) {
	url := fmt.Sprintf("%s/%s/%s", sdk.computationsURL, computationsEndpoint, id)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return Computation{}, err
	}

	resp, err := sdk.sendRequest(req, token, string(CTJSON))
	if err != nil {
		return Computation{}, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return Computation{}, err
	}

	if resp.StatusCode != http.StatusOK {
		return Computation{}, errors.New("failed to fetch entity")
	}

	var c Computation
	if err := json.Unmarshal(body, &c); err != nil {
		return Computation{}, err
	}

	return c, nil
}

func (sdk cSDK) UpdateComputation(c Computation, token string) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/%s/%s", sdk.computationsURL, computationsEndpoint, c.ID)

	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(data))
	if err != nil {
		return err
	}

	resp, err := sdk.sendRequest(req, token, string(CTJSON))
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return errors.New("failed to update entity")
	}

	return nil
}

func (sdk cSDK) DeleteComputation(id, token string) error {
	url := fmt.Sprintf("%s/%s/%s", sdk.computationsURL, computationsEndpoint, id)

	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return err
	}

	resp, err := sdk.sendRequest(req, token, string(CTJSON))
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusNoContent {
		return errors.New("failed to remove entity")
	}

	return nil
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
