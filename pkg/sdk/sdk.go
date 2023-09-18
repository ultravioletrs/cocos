package sdk

type SDK interface {
	Run(computation Computation) (string, error)
	UploadAlgorithm(algorithm []byte) (string, error)
	UploadDataset(dataset []byte) (string, error)
	Result() ([]byte, error)
}
