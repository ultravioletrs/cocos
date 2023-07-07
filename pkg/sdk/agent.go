package sdk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

type Computation struct {
	ID                 string    `json:"id,omitempty" db:"id"`
	Name               string    `json:"name,omitempty" db:"name"`
	Description        string    `json:"description,omitempty" db:"description"`
	Status             string    `json:"status,omitempty" db:"status"`
	Owner              string    `json:"owner,omitempty" db:"owner"`
	StartTime          time.Time `json:"start_time,omitempty" db:"start_time"`
	EndTime            time.Time `json:"end_time,omitempty" db:"end_time"`
	Datasets           []string  `json:"datasets,omitempty" db:"datasets"`
	Algorithms         []string  `json:"algorithms,omitempty" db:"algorithms"`
	DatasetProviders   []string  `json:"dataset_providers,omitempty" db:"dataset_providers"`
	AlgorithmProviders []string  `json:"algorithm_providers,omitempty" db:"algorithm_providers"`
	ResultConsumers    []string  `json:"result_consumers,omitempty" db:"result_consumers"`
	Ttl                int       `json:"ttl,omitempty" db:"ttl"`
	Metadata           Metadata  `json:"metadata,omitempty" db:"metadata"`
}

func (sdk *agentSDK) Ping(url string) (string, error) {
	data := fmt.Sprintf("%s%s", sdk.agentURL, url)

	req, err := http.NewRequest(http.MethodGet, data, nil)
	if err != nil {
		return "", err
	}

	resp, err := sdk.sendRequest(req, "", ctJSON)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	response := string(body)

	return response, nil
}

func (sdk *agentSDK) Run(computation Computation) (string, error) {
	cmpJSON, err := json.Marshal(computation)
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("%s/run", sdk.agentURL)

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(cmpJSON))
	if err != nil {
		return "", err
	}

	resp, err := sdk.sendRequest(req, "", ctJSON)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	response := string(body)

	return response, nil
}

func (sdk *agentSDK) UploadAlgorithm(algorithm []byte) (string, error) {
	url := fmt.Sprintf("%s/algo", sdk.agentURL)

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(algorithm))
	if err != nil {
		return "", err
	}

	resp, err := sdk.sendRequest(req, "", ctJSON)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	response := string(body)

	return response, nil
}

func (sdk *agentSDK) UploadDataset(dataset string) (string, error) {
	url := fmt.Sprintf("%s/data/%s", sdk.agentURL, dataset)

	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := sdk.sendRequest(req, "", ctJSON)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	response := string(body)

	return response, nil
}

func (sdk *agentSDK) Result() ([]byte, error) {
	url := fmt.Sprintf("%s/result", sdk.agentURL)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := sdk.sendRequest(req, "", ctJSON)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}
