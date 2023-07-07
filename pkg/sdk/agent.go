package sdk

import "time"

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

func (sdk agentSDK) Ping(url string) (string, error)

func (sdk agentSDK) Run(computation Computation) (string, error)

func (sdk agentSDK) Algo(algorithm []byte) (string, error)

func (sdk agentSDK) Data(dataset string) (string, error)

func (sdk agentSDK) Result() ([]byte, error)
