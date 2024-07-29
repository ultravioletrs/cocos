// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
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
	"github.com/ultravioletrs/cocos/agent/events"
	"google.golang.org/grpc/metadata"
)

const (
	containerName       = "agent_container"
	containerOutputFile = "/cocos/result"
	containerWorkingDir = "/cocos"
	DockerRunCommand    = "python3,/cocos/algorithm.py"
	dockerRunCommandKey = "docker_run_command"
)

var _ algorithm.Algorithm = (*docker)(nil)

type docker struct {
	algoFile   string
	datasets   []string
	logger     *slog.Logger
	stderr     io.Writer
	stdout     io.Writer
	runCommand string
}

func DockerRunCommandToContext(ctx context.Context, runCommand string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, dockerRunCommandKey, runCommand)
}

func DockerRunCommandFromContext(ctx context.Context) string {
	return metadata.ValueFromIncomingContext(ctx, dockerRunCommandKey)[0]
}

func New(logger *slog.Logger, eventsSvc events.Service, runCommand, algoFile string) algorithm.Algorithm {
	d := &docker{
		algoFile: algoFile,
		logger:   logger,
		stderr:   &algorithm.Stderr{Logger: logger, EventSvc: eventsSvc},
		stdout:   &algorithm.Stdout{Logger: logger},
	}

	if runCommand == "" {
		d.runCommand = DockerRunCommand
	} else {
		d.runCommand = runCommand
	}

	return d
}
func (d *docker) Run() ([]byte, error) {
	ctx := context.Background()

	// Create a new Docker client.
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return []byte{}, fmt.Errorf("could not create a new Docker client: %v", err)
	}

	// Open the Docker image tar file.
	imageFile, err := os.Open(d.algoFile)
	if err != nil {
		return []byte{}, fmt.Errorf("could not open Docker image: %v", err)
	}
	defer imageFile.Close()

	// Load the Docker image from the tar file.
	resp, err := cli.ImageLoad(ctx, imageFile, true)
	if err != nil {
		return []byte{}, fmt.Errorf("could not load Docker image from file: %v", err)
	}
	defer resp.Body.Close()

	// List the loaded images to get the image ID.
	images, err := cli.ImageList(ctx, image.ListOptions{})
	if err != nil {
		return []byte{}, fmt.Errorf("could not get the Docker image list: %v", err)
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
		return []byte{}, fmt.Errorf("could not find image ID")
	}

	dataFileNames := make([]string, len(d.datasets))

	for i, dataPath := range d.datasets {
		dataFileNames[i] = path.Join(containerWorkingDir, algorithm.DatasetDirectory, filepath.Base(dataPath))
	}

	dockerCommand := strings.Split(d.runCommand, ",")
	dockerCommand = append(dockerCommand, strings.Join(dataFileNames, " "))

	// Create and start the container.
	respContainer, err := cli.ContainerCreate(ctx, &container.Config{
		Image: dockerImageName,
		Cmd:   dockerCommand,
	}, &container.HostConfig{
		Mounts: []mount.Mount{
			{
				Type:   mount.TypeBind,
				Source: algorithm.DatasetDirectory,
				Target: path.Join(containerWorkingDir, algorithm.DatasetDirectory),
			},
		},
	}, nil, nil, containerName)

	if err != nil {
		return []byte{}, fmt.Errorf("could not create a Docker container: %v", err)
	}

	if err := cli.ContainerStart(ctx, respContainer.ID, container.StartOptions{}); err != nil {
		return []byte{}, fmt.Errorf("could not start a Docker container: %v", err)
	}

	statusCh, errCh := cli.ContainerWait(ctx, respContainer.ID, container.WaitConditionNotRunning)
	select {
	case err := <-errCh:
		if err != nil {
			return []byte{}, fmt.Errorf("could not wait for a Docker container: %v", err)
		}
	case <-statusCh:
	}

	agentResultOutput := path.Join(algorithm.AlgorithmResultOutputDir, algorithm.AlgorithmResultOutputFile)

	if err := copyFromContainer(cli, containerName, containerOutputFile, agentResultOutput); err != nil {
		return []byte{}, fmt.Errorf("could not copy from the Docker container: %v", err)
	}

	resultBytes, err := os.ReadFile(agentResultOutput)
	if err != nil {
		return []byte{}, fmt.Errorf("could not read bytes from the result file: %v", err)
	}

	stdout, err := cli.ContainerLogs(ctx, respContainer.ID, container.LogsOptions{ShowStdout: true})
	if err != nil {
		return []byte{}, fmt.Errorf("could not read stdout from the container: %v", err)
	}
	defer stdout.Close()

	err = writeToOut(stdout, d.stdout)
	if err != nil {
		d.logger.Warn(fmt.Sprintf("could not write to stdout: %v", err))
	}

	stderr, err := cli.ContainerLogs(ctx, respContainer.ID, container.LogsOptions{ShowStderr: true})
	if err != nil {
		d.logger.Warn(fmt.Sprintf("could not read stderr from the container: %v", err))
	}
	defer stderr.Close()

	err = writeToOut(stderr, d.stderr)
	if err != nil {
		d.logger.Warn(fmt.Sprintf("could not write to stderr: %v", err))
	}

	if err = cli.ContainerRemove(ctx, respContainer.ID, container.RemoveOptions{Force: true}); err != nil {
		return []byte{}, fmt.Errorf("could not remove container: %v", err)
	}

	if _, err := cli.ImageRemove(ctx, imageID, image.RemoveOptions{Force: true}); err != nil {
		return []byte{}, fmt.Errorf("could not remove image: %v", err)
	}

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

func (d *docker) AddDataset(dataset string) {
	d.datasets = append(d.datasets, dataset)
}

func writeToOut(readCloser io.ReadCloser, ioWriter io.Writer) error {
	content, err := io.ReadAll(readCloser)
	if err != nil {
		return fmt.Errorf("could not convert content from the container: %v", err)
	}

	if _, err := ioWriter.Write(content); err != nil {
		return fmt.Errorf("could not write to output: %v", err)
	}

	return nil
}
