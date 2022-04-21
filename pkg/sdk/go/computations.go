package sdk

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

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

func (sdk csdk) CreateComputation(c Computation, token string) (string, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("%s/%s", sdk.computationsURL, computationsEndpoint)

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return "", err
	}

	resp, err := sdk.sendRequest(req, token, ctJSON)
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

func (sdk csdk) ListComputations(token string, offset, limit uint64, name string) (ComputationsPage, error) {
	endpoint := fmt.Sprintf("%s?offset=%d&limit=%d&name=%s", computationsEndpoint, offset, limit, name)
	url := fmt.Sprintf("%s/%s", sdk.computationsURL, endpoint)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return ComputationsPage{}, err
	}

	resp, err := sdk.sendRequest(req, token, ctJSON)
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

func (sdk csdk) GetComputation(id, token string) (Computation, error) {
	url := fmt.Sprintf("%s/%s/%s", sdk.computationsURL, computationsEndpoint, id)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return Computation{}, err
	}

	resp, err := sdk.sendRequest(req, token, ctJSON)
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

func (sdk csdk) UpdateComputation(c Computation, token string) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/%s/%s", sdk.computationsURL, computationsEndpoint, c.ID)

	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(data))
	if err != nil {
		return err
	}

	resp, err := sdk.sendRequest(req, token, ctJSON)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return errors.New("failed to update entity")
	}

	return nil
}

func (sdk csdk) DeleteComputation(id, token string) error {
	url := fmt.Sprintf("%s/%s/%s", sdk.computationsURL, computationsEndpoint, id)

	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return err
	}

	resp, err := sdk.sendRequest(req, token, ctJSON)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusNoContent {
		return errors.New("failed to remove entity")
	}

	return nil
}
