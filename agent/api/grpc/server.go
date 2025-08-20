// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/transport/grpc"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/quoteprovider"
	"github.com/ultravioletrs/cocos/pkg/attestation/vtpm"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	bufferSize  = 1024 * 1024
	FileSizeKey = "file-size"
)

var (
	ErrTEENonceLength   = errors.New("malformed report data, expect less or equal to 64 bytes")
	ErrVTPMNonceLength  = errors.New("malformed vTPM nonce, expect less or equal to 32 bytes")
	ErrTokenNonceLength = errors.New("malformed token nonce, expect less or equal to 32 bytes")
)

var _ agent.AgentServiceServer = (*grpcServer)(nil)

type grpcServer struct {
	handlers map[string]grpc.Handler
	agent.UnimplementedAgentServiceServer
}

type endpointConfig struct {
	endpoint       func(agent.Service) endpoint.Endpoint
	decodeRequest  grpc.DecodeRequestFunc
	encodeResponse grpc.EncodeResponseFunc
}

// NewServer returns new AgentServiceServer instance.
func NewServer(svc agent.Service) agent.AgentServiceServer {
	// Define endpoint configurations
	endpoints := map[string]endpointConfig{
		"algo": {
			endpoint:       algoEndpoint,
			decodeRequest:  decodeAlgoRequest,
			encodeResponse: encodeAlgoResponse,
		},
		"data": {
			endpoint:       dataEndpoint,
			decodeRequest:  decodeDataRequest,
			encodeResponse: encodeDataResponse,
		},
		"result": {
			endpoint:       resultEndpoint,
			decodeRequest:  decodeResultRequest,
			encodeResponse: encodeResultResponse,
		},
		"attestation": {
			endpoint:       attestationEndpoint,
			decodeRequest:  decodeAttestationRequest,
			encodeResponse: encodeAttestationResponse,
		},
		"imaMeasurements": {
			endpoint:       imaMeasurementsEndpoint,
			decodeRequest:  decodeIMAMeasurementsRequest,
			encodeResponse: encodeIMAMeasurementsResponse,
		},
		"azureAttestationToken": {
			endpoint:       azureAttestationTokenEndpoint,
			decodeRequest:  decodeAttestationTokenRequest,
			encodeResponse: encodeAttestationTokenResponse,
		},
	}

	// Create handlers using the configurations
	handlers := make(map[string]grpc.Handler)
	for name, config := range endpoints {
		handlers[name] = grpc.NewServer(
			config.endpoint(svc),
			config.decodeRequest,
			config.encodeResponse,
		)
	}

	return &grpcServer{
		handlers: handlers,
	}
}

func decodeAlgoRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(*agent.AlgoRequest)
	return algoReq{
		Algorithm:    req.Algorithm,
		Requirements: req.Requirements,
	}, nil
}

func encodeAlgoResponse(_ context.Context, response interface{}) (interface{}, error) {
	return &agent.AlgoResponse{}, nil
}

func decodeDataRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(*agent.DataRequest)
	return dataReq{
		Dataset:  req.Dataset,
		Filename: req.Filename,
	}, nil
}

func encodeDataResponse(_ context.Context, response interface{}) (interface{}, error) {
	return &agent.DataResponse{}, nil
}

func decodeResultRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	return resultReq{}, nil
}

func encodeResultResponse(_ context.Context, response interface{}) (interface{}, error) {
	res := response.(resultRes)
	return &agent.ResultResponse{
		File: res.File,
	}, nil
}

func validateNonce(nonce []byte, maxLen int, target interface{}) error {
	if len(nonce) > maxLen {
		switch maxLen {
		case quoteprovider.Nonce:
			return ErrTEENonceLength
		case vtpm.Nonce:
			return ErrVTPMNonceLength
		default:
			return ErrTokenNonceLength
		}
	}

	switch t := target.(type) {
	case *[quoteprovider.Nonce]byte:
		copy(t[:], nonce)
	case *[vtpm.Nonce]byte:
		copy(t[:], nonce)
	default:
		return fmt.Errorf("unsupported target type for nonce validation: %T", target)
	}
	return nil
}

func decodeAttestationRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(*agent.AttestationRequest)
	var reportData [quoteprovider.Nonce]byte
	var nonce [vtpm.Nonce]byte

	if err := validateNonce(req.TeeNonce, quoteprovider.Nonce, &reportData); err != nil {
		return nil, err
	}

	if err := validateNonce(req.VtpmNonce, vtpm.Nonce, &nonce); err != nil {
		return nil, err
	}

	return attestationReq{
		TeeNonce:  reportData,
		VtpmNonce: nonce,
		AttType:   attestation.PlatformType(req.Type),
	}, nil
}

func encodeAttestationResponse(_ context.Context, response interface{}) (interface{}, error) {
	res := response.(attestationRes)
	return &agent.AttestationResponse{
		File: res.File,
	}, nil
}

func decodeAttestationTokenRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(*agent.AttestationTokenRequest)
	var nonce [vtpm.Nonce]byte

	if err := validateNonce(req.TokenNonce, vtpm.Nonce, &nonce); err != nil {
		return nil, err
	}
	return azureAttestationTokenReq{
		tokenNonce: nonce,
	}, nil
}

func encodeAttestationTokenResponse(_ context.Context, response interface{}) (interface{}, error) {
	res := response.(fetchAttestationTokenRes)
	return &agent.AttestationTokenResponse{
		File: res.File,
	}, nil
}

func decodeIMAMeasurementsRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	return imaMeasurementsReq{}, nil
}

func encodeIMAMeasurementsResponse(_ context.Context, response interface{}) (interface{}, error) {
	res := response.(imaMeasurementsRes)
	return &agent.IMAMeasurementsResponse{
		File:  res.File,
		Pcr10: res.PCR10,
	}, nil
}

func (s *grpcServer) streamingHandler(
	ctx context.Context,
	handlerName string,
	req interface{},
	stream interface{},
	sendFn func([]byte) error,
	getFileData func(interface{}) []byte,
) error {
	handler, ok := s.handlers[handlerName]
	if !ok {
		return status.Errorf(codes.NotFound, "handler %q not found", handlerName)
	}

	_, res, err := handler.ServeGRPC(ctx, req)
	if err != nil {
		return err
	}

	fileData := getFileData(res)

	// Set file size header
	if setter, ok := stream.(interface{ SetHeader(metadata.MD) error }); ok {
		if err := setter.SetHeader(metadata.New(map[string]string{
			FileSizeKey: fmt.Sprint(len(fileData)),
		})); err != nil {
			return status.Error(codes.Internal, err.Error())
		}
	}

	// Stream the file data
	return s.streamFileData(bytes.NewBuffer(fileData), sendFn)
}

func (s *grpcServer) streamFileData(buffer *bytes.Buffer, sendFn func([]byte) error) error {
	buf := make([]byte, bufferSize)
	for {
		n, err := buffer.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return status.Error(codes.Internal, err.Error())
		}

		if err := sendFn(buf[:n]); err != nil {
			return status.Error(codes.Internal, err.Error())
		}
	}
	return nil
}

func receiveStreamingData(getData func() ([]byte, string, error)) ([]byte, string, error) {
	var data []byte
	var filename string

	for {
		chunk, fname, err := getData()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, "", status.Error(codes.Internal, err.Error())
		}
		data = append(data, chunk...)
		if fname != "" {
			filename = fname
		}
	}
	return data, filename, nil
}

// Algo implements agent.AgentServiceServer.
func (s *grpcServer) Algo(stream agent.AgentService_AlgoServer) error {
	algoFile, reqFile, err := s.receiveAlgoData(stream)
	if err != nil {
		return err
	}

	_, res, err := s.handlers["algo"].ServeGRPC(stream.Context(), &agent.AlgoRequest{
		Algorithm:    algoFile,
		Requirements: reqFile,
	})
	if err != nil {
		return err
	}

	return stream.SendAndClose(res.(*agent.AlgoResponse))
}

func (s *grpcServer) receiveAlgoData(stream agent.AgentService_AlgoServer) ([]byte, []byte, error) {
	var algoFile, reqFile []byte
	for {
		chunk, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, status.Error(codes.Internal, err.Error())
		}
		algoFile = append(algoFile, chunk.Algorithm...)
		reqFile = append(reqFile, chunk.Requirements...)
	}
	return algoFile, reqFile, nil
}

// Data implements agent.AgentServiceServer.
func (s *grpcServer) Data(stream agent.AgentService_DataServer) error {
	dataFile, filename, err := receiveStreamingData(func() ([]byte, string, error) {
		chunk, err := stream.Recv()
		if err != nil {
			return nil, "", err
		}
		return chunk.Dataset, chunk.Filename, nil
	})
	if err != nil {
		return err
	}

	_, res, err := s.handlers["data"].ServeGRPC(stream.Context(), &agent.DataRequest{
		Dataset:  dataFile,
		Filename: filename,
	})
	if err != nil {
		return err
	}

	return stream.SendAndClose(res.(*agent.DataResponse))
}

func (s *grpcServer) Result(req *agent.ResultRequest, stream agent.AgentService_ResultServer) error {
	return s.streamingHandler(
		stream.Context(),
		"result",
		req,
		stream,
		func(data []byte) error {
			return stream.Send(&agent.ResultResponse{File: data})
		},
		func(res interface{}) []byte {
			return res.(*agent.ResultResponse).File
		},
	)
}

func (s *grpcServer) Attestation(req *agent.AttestationRequest, stream agent.AgentService_AttestationServer) error {
	return s.streamingHandler(
		stream.Context(),
		"attestation",
		req,
		stream,
		func(data []byte) error {
			return stream.Send(&agent.AttestationResponse{File: data})
		},
		func(res interface{}) []byte {
			return res.(*agent.AttestationResponse).File
		},
	)
}

func (s *grpcServer) IMAMeasurements(req *agent.IMAMeasurementsRequest, stream agent.AgentService_IMAMeasurementsServer) error {
	_, res, err := s.handlers["imaMeasurements"].ServeGRPC(stream.Context(), req)
	if err != nil {
		return err
	}
	rr := res.(*agent.IMAMeasurementsResponse)

	if err := stream.SetHeader(metadata.New(map[string]string{
		FileSizeKey: strconv.Itoa(len(rr.File)),
	})); err != nil {
		return status.Error(codes.Internal, err.Error())
	}

	return s.streamDualBuffers(
		bytes.NewBuffer(rr.File),
		bytes.NewBuffer(rr.Pcr10),
		func(fileData, pcr10Data []byte) error {
			return stream.Send(&agent.IMAMeasurementsResponse{
				File:  fileData,
				Pcr10: pcr10Data,
			})
		},
	)
}

func (s *grpcServer) AttestationToken(ctx context.Context, req *agent.AttestationTokenRequest) (*agent.AttestationTokenResponse, error) {
	_, res, err := s.handlers["azureAttestationToken"].ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}

	rr, ok := res.(*agent.AttestationTokenResponse)
	if !ok {
		return nil, status.Error(codes.Internal, "failed to cast response to AttestationTokenResponse")
	}

	return rr, nil
}

func (s *grpcServer) streamDualBuffers(
	buf1, buf2 *bytes.Buffer,
	sendFn func([]byte, []byte) error,
) error {
	buff1 := make([]byte, bufferSize)
	buff2 := make([]byte, bufferSize)

	for {
		n1, err1 := buf1.Read(buff1)
		if err1 != nil && err1 != io.EOF {
			return status.Error(codes.Internal, err1.Error())
		}

		n2, err2 := buf2.Read(buff2)
		if err2 != nil && err2 != io.EOF {
			return status.Error(codes.Internal, err2.Error())
		}

		if n1 == 0 && err1 == io.EOF && n2 == 0 && err2 == io.EOF {
			break
		}

		if err := sendFn(buff1[:n1], buff2[:n2]); err != nil {
			return status.Error(codes.Internal, err.Error())
		}
	}
	return nil
}
