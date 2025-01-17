// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package docker

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	"github.com/ultravioletrs/cocos/agent/algorithm"
	"github.com/ultravioletrs/cocos/agent/algorithm/logging"
	"github.com/ultravioletrs/cocos/agent/events"
)

const (
	containerName     = "agent_container"
	datasetsMountPath = "/cocos/datasets"
	resultsMountPath  = "/cocos/results"
)

var _ algorithm.Algorithm = (*docker)(nil)

type docker struct {
	algoFile string
	logger   *slog.Logger
	stderr   io.Writer
	stdout   io.Writer
}

func NewAlgorithm(logger *slog.Logger, eventsSvc events.Service, algoFile, cmpID string) algorithm.Algorithm {
	d := &docker{
		algoFile: algoFile,
		logger:   logger,
		stderr:   &logging.Stderr{Logger: logger, EventSvc: eventsSvc, CmpID: cmpID},
		stdout:   &logging.Stdout{Logger: logger},
	}

	return d
}

func (d *docker) Run() error {
	// Create a new Docker client.
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("could not create a new Docker client: %v", err)
	}

	// Open the Docker image tar file.
	imageFile, err := os.Open(d.algoFile)
	if err != nil {
		return fmt.Errorf("could not open Docker image: %v", err)
	}
	defer imageFile.Close()

	ctx := context.Background()
	// Load the Docker image from the tar file.
	resp, err := cli.ImageLoad(ctx, imageFile, true)
	if err != nil {
		return fmt.Errorf("could not load Docker image from file: %v", err)
	}
	defer resp.Body.Close()

	// List the loaded images to get the image ID.
	images, err := cli.ImageList(ctx, image.ListOptions{})
	if err != nil {
		return fmt.Errorf("could not get the Docker image list: %v", err)
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
		return fmt.Errorf("could not find image ID")
	}

	// Create and start the container.
	respContainer, err := cli.ContainerCreate(ctx, &container.Config{
		Image:        dockerImageName,
		Tty:          true,
		AttachStdout: true,
		AttachStderr: true,
	}, &container.HostConfig{
		Mounts: []mount.Mount{
			{
				Type:   mount.TypeBind,
				Source: path.Join(algorithm.AlgoWorkingDir, algorithm.DatasetsDir),
				Target: datasetsMountPath,
			},
			{
				Type:   mount.TypeBind,
				Source: path.Join(algorithm.AlgoWorkingDir, algorithm.ResultsDir),
				Target: resultsMountPath,
			},
		},
	}, nil, nil, containerName)
	if err != nil {
		return fmt.Errorf("could not create a Docker container: %v", err)
	}

	if err := cli.ContainerStart(ctx, respContainer.ID, container.StartOptions{}); err != nil {
		return fmt.Errorf("could not start a Docker container: %v", err)
	}

	stdout, err := cli.ContainerLogs(ctx, respContainer.ID, container.LogsOptions{ShowStdout: true, Follow: true})
	if err != nil {
		return fmt.Errorf("could not read stdout from the container: %v", err)
	}
	defer stdout.Close()

	go func() {
		if err := writeToOut(stdout, d.stdout); err != nil {
			d.logger.Warn(fmt.Sprintf("could not write to stdout: %v", err))
		}
	}()

	stderr, err := cli.ContainerLogs(ctx, respContainer.ID, container.LogsOptions{ShowStderr: true, Follow: true})
	if err != nil {
		d.logger.Warn(fmt.Sprintf("could not read stderr from the container: %v", err))
	}
	defer stderr.Close()

	go func() {
		if err := writeToOut(stderr, d.stderr); err != nil {
			d.logger.Warn(fmt.Sprintf("could not write to stderr: %v", err))
		}
	}()

	statusCh, errCh := cli.ContainerWait(ctx, respContainer.ID, container.WaitConditionNotRunning)
	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("could not wait for a Docker container: %v", err)
		}
	case <-statusCh:
	}

	defer func() {
		if err = cli.ContainerRemove(ctx, respContainer.ID, container.RemoveOptions{Force: true}); err != nil {
			d.logger.Warn(fmt.Sprintf("error could not remove container: %v", err))
		}

		if _, err := cli.ImageRemove(ctx, imageID, image.RemoveOptions{Force: true}); err != nil {
			d.logger.Warn(fmt.Sprintf("error could not remove image: %v", err))
		}
	}()

	return nil
}

func writeToOut(readCloser io.ReadCloser, ioWriter io.Writer) error {
	scanner := bufio.NewScanner(readCloser)
	for scanner.Scan() {
		if _, err := ioWriter.Write(scanner.Bytes()); err != nil {
			return fmt.Errorf("error writing to output: %v", err)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading container logs error: %v", err)
	}

	return nil
}

func (d *docker) Stop() error {
	// To be supported later.
	return nil
}
