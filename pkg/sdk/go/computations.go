package sdk

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

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
		return ComputationsPage{}, errors.New("Fail to create")
	}

	var tp ComputationsPage
	if err := json.Unmarshal(body, &tp); err != nil {
		return ComputationsPage{}, err
	}

	return tp, nil
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
		return errors.New("Fail to create")
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
