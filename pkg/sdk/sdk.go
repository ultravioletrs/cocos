package sdk

import (
	"time"

	"github.com/mainflux/mainflux/logger"
)

type Config struct {
	AgentURL     string
	AgentTimeout time.Duration
	JaegerURL    string // Add JaegerURL field
}

type SDK interface {
	Run(computation Computation) (string, error)
	UploadAlgorithm(algorithm []byte) (string, error)
	UploadDataset(dataset string) (string, error)
	Result() ([]byte, error)
}

func NewSDK(conf Config, log logger.Logger) (SDK, error) {
	return NewAgentSDK(conf, log)
}
