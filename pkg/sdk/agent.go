package sdk

import (
	"bytes"
	"encoding/json"
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
	req, err := http.NewRequest("GET", sdk.agentURL+url, nil)
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

	req, err := http.NewRequest(http.MethodPost, sdk.agentURL+"/run", bytes.NewBuffer(cmpJSON))
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

func (sdk *agentSDK) Algo(algorithm []byte) (string, error) {
	req, err := http.NewRequest(http.MethodPost, sdk.agentURL+"/algo", bytes.NewBuffer(algorithm))
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

func (sdk *agentSDK) Data(dataset string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, sdk.agentURL+"/data/"+dataset, nil)
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
	req, err := http.NewRequest(http.MethodGet, sdk.agentURL+"/result", nil)
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
