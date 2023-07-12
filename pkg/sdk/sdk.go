package sdk

type Config struct {
	AgentURL string
}

type SDK interface {
	Run(computation Computation) (string, error)
	UploadAlgorithm(algorithm []byte) (string, error)
	UploadDataset(dataset string) (string, error)
	Result() ([]byte, error)
	Close()
}

func NewSDK(conf Config) (SDK, error) {
	return NewAgentSDK(conf)
}
