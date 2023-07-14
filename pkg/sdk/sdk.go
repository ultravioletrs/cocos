package sdk

type SDK interface {
	Run(computation Computation) (string, error)
	UploadAlgorithm(algorithm []byte) (string, error)
	UploadDataset(dataset string) (string, error)
	Result() ([]byte, error)
}
