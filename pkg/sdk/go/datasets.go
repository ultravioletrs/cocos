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

const datasetsEndpoint = "datasets"

type Dataset struct {
	ID          string                 `json:"id,omitempty" db:"id"`
	Name        string                 `json:"name,omitempty" db:"name"`
	Description string                 `json:"description,omitempty" db:"description"`
	Owner       string                 `json:"owner,omitempty" db:"owner"`
	Size        uint64                 `json:"size,omitempty" db:"size"`
	CreatedAt   time.Time              `json:"created_at,omitempty" db:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at,omitempty" db:"updated_at"`
	Location    string                 `json:"location,omitempty" db:"location"`
	Format      string                 `json:"format,omitempty" db:"format"`
	Metadata    map[string]interface{} `json:"metadata,omitempty" db:"metadata"`
	Path        string                 `json:"Path,omitempty" db:"path"`
}

type DatasetsPage struct {
	Dataset []Dataset `json:"datasets"`
	pageRes
}

func (sdk csdk) CreateDataset(d Dataset, token string) (string, error) {
	data, err := json.Marshal(d)
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("%s/%s", sdk.datasetsURL, datasetsEndpoint)

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

	id := strings.TrimPrefix(resp.Header.Get("Location"), fmt.Sprintf("/%s/", datasetsEndpoint))
	return id, nil
}

func (sdk csdk) ListDatasets(token string, offset, limit uint64, name string) (DatasetsPage, error) {
	endpoint := fmt.Sprintf("%s?offset=%d&limit=%d&name=%s", datasetsEndpoint, offset, limit, name)
	url := fmt.Sprintf("%s/%s", sdk.datasetsURL, endpoint)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return DatasetsPage{}, err
	}

	resp, err := sdk.sendRequest(req, token, ctJSON)
	if err != nil {
		return DatasetsPage{}, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return DatasetsPage{}, err
	}

	if resp.StatusCode != http.StatusOK {
		return DatasetsPage{}, errors.New("failed to list datasets")
	}

	var tp DatasetsPage
	if err := json.Unmarshal(body, &tp); err != nil {
		return DatasetsPage{}, err
	}

	return tp, nil
}

func (sdk csdk) Dataset(id, token string) (Dataset, error) {
	url := fmt.Sprintf("%s/%s/%s", sdk.datasetsURL, datasetsEndpoint, id)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return Dataset{}, err
	}

	resp, err := sdk.sendRequest(req, token, ctJSON)
	if err != nil {
		return Dataset{}, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return Dataset{}, err
	}

	if resp.StatusCode != http.StatusOK {
		return Dataset{}, errors.New("failed to fetch entity")
	}

	var d Dataset
	if err := json.Unmarshal(body, &d); err != nil {
		return Dataset{}, err
	}

	return d, nil
}

func (sdk csdk) UpdateDataset(d Dataset, token string) error {
	data, err := json.Marshal(d)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/%s/%s", sdk.datasetsURL, datasetsEndpoint, d.ID)

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

func (sdk csdk) DeleteDataset(id, token string) error {
	url := fmt.Sprintf("%s/%s/%s", sdk.datasetsURL, datasetsEndpoint, id)

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
