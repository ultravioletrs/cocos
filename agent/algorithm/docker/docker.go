package docker

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	"github.com/ultravioletrs/cocos/agent/algorithm"
)

const (
	dataTMPDirectory    = "data"
	containerName       = "agent_container"
	agentResultOutput   = "/run/result"
	algoName            = "/cocos/algorithm.py"
	containerOutputFile = "/cocos/model.pth"
	containerWorkingDir = "/cocos"
)

var _ algorithm.Algorithm = (*Docker)(nil)

type Docker struct {
	logger *slog.Logger
}

func New(logger *slog.Logger) algorithm.Algorithm {
	return &Docker{
		logger: logger,
	}
}
func (d *Docker) Run(algoFile string, dataFiles []string) ([]byte, error) {
	ctx := context.Background()

	// Create a new Docker client.
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return []byte{}, fmt.Errorf("could not create a new Docker client: %v", err)
	}

	// Open the Docker image tar file.
	imageFile, err := os.Open(algoFile)
	if err != nil {
		return []byte{}, fmt.Errorf("couldn not open Docker image: %v", err)
	}
	defer imageFile.Close()

	// Load the Docker image from the tar file.
	resp, err := cli.ImageLoad(ctx, imageFile, true)
	if err != nil {
		return []byte{}, fmt.Errorf("couldn not load Docker image from file: %v", err)
	}
	defer resp.Body.Close()

	// List the loaded images to get the image ID.
	images, err := cli.ImageList(ctx, image.ListOptions{})
	if err != nil {
		return []byte{}, fmt.Errorf("couldn not get the Docker image list: %v", err)
	}

	var imageID string = ""
	var dockerImageName string = ""
	for _, image := range images {
		for _, tag := range image.RepoTags {
			imageID = image.ID
			dockerImageName = tag
			break
		}
	}

	if imageID == "" {
		return []byte{}, fmt.Errorf("couldn not find image ID")
	}

	dataFileNames := make([]string, len(dataFiles))

	for i, dataPath := range dataFiles {
		dataFileNames[i] = path.Join(containerWorkingDir, dataTMPDirectory, filepath.Base(dataPath))
	}

	// Create and start the container.
	respContainer, err := cli.ContainerCreate(ctx, &container.Config{
		Image: dockerImageName,
		Cmd:   []string{"python3", algoName, strings.Join(dataFileNames, " ")},
	}, &container.HostConfig{
		Mounts: []mount.Mount{
			{
				Type:   mount.TypeBind,
				Source: path.Join(os.TempDir(), dataTMPDirectory),
				Target: path.Join(containerWorkingDir, dataTMPDirectory),
			},
		},
	}, nil, nil, containerName)

	if err != nil {
		return []byte{}, fmt.Errorf("couldn not create a Docker container: %v", err)
	}

	if err := cli.ContainerStart(ctx, respContainer.ID, container.StartOptions{}); err != nil {
		return []byte{}, fmt.Errorf("couldn not start a Docker container: %v", err)
	}

	statusCh, errCh := cli.ContainerWait(ctx, respContainer.ID, container.WaitConditionNotRunning)
	select {
	case err := <-errCh:
		if err != nil {
			return []byte{}, fmt.Errorf("couldn not wait for a Docker container: %v", err)
		}
	case <-statusCh:
	}

	if err := copyFromContainer(cli, containerName, containerOutputFile, agentResultOutput); err != nil {
		return []byte{}, fmt.Errorf("couldn not copy from the Docker container: %v", err)
	}

	resultBytes, err := os.ReadFile(agentResultOutput)
	if err != nil {
		return []byte{}, fmt.Errorf("could not read bytes from the result file: %v", err)
	}

	out, err := cli.ContainerLogs(ctx, respContainer.ID, container.LogsOptions{ShowStdout: true})
	if err != nil {
		return []byte{}, fmt.Errorf("could not read stdOut from the container: %v", err)
	}
	defer out.Close()

	content, err := io.ReadAll(out)
	if err != nil {
		return []byte{}, fmt.Errorf("could not convert stdOut from the container: %v", err)
	}

	d.logger.Debug(string(content))

	return resultBytes, nil
}

func copyFromContainer(cli *client.Client, containerID, containerFilePath, hostFilePath string) error {
	ctx := context.Background()
	reader, _, err := cli.CopyFromContainer(ctx, containerID, containerFilePath)
	if err != nil {
		return fmt.Errorf("failed to copy from container: %v", err)
	}
	defer reader.Close()

	// Create the destination file.
	hostFile, err := os.Create(hostFilePath)
	if err != nil {
		return fmt.Errorf("failed to create host file: %v", err)
	}
	defer hostFile.Close()

	tarReader := tar.NewReader(reader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("error reading tar archive: %v", err)
		}

		if header.Typeflag == tar.TypeReg && header.Name == filepath.Base(containerFilePath) {
			hostFile, err := os.Create(hostFilePath)
			if err != nil {
				return fmt.Errorf("failed to create host file: %v", err)
			}
			defer hostFile.Close()

			if _, err := io.Copy(hostFile, tarReader); err != nil {
				return fmt.Errorf("failed to copy data to host file: %v", err)
			}
		}
	}

	return nil
}
