// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/go-kit/kit/transport/grpc"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/pkg/attestation/vtpm"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	bufferSize  = 1024 * 1024
	FileSizeKey = "file-size"
)

var _ agent.AgentServiceServer = (*grpcServer)(nil)

type grpcServer struct {
	algo        grpc.Handler
	data        grpc.Handler
	result      grpc.Handler
	attestation grpc.Handler
	agent.UnimplementedAgentServiceServer
}

// NewServer returns new AgentServiceServer instance.
func NewServer(svc agent.Service) agent.AgentServiceServer {
	return &grpcServer{
		algo: grpc.NewServer(
			algoEndpoint(svc),
			decodeAlgoRequest,
			encodeAlgoResponse,
		),
		data: grpc.NewServer(
			dataEndpoint(svc),
			decodeDataRequest,
			encodeDataResponse,
		),
		result: grpc.NewServer(
			resultEndpoint(svc),
			decodeResultRequest,
			encodeResultResponse,
		),
		attestation: grpc.NewServer(
			attestationEndpoint(svc),
			decodeAttestationRequest,
			encodeAttestationResponse,
		),
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

func decodeAttestationRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(*agent.AttestationRequest)
	var reportData [agent.Nonce]byte
	var nonce [vtpm.Nonce]byte

	if len(req.TeeNonce) > agent.Nonce {
		return nil, errors.New("malformed report data, expect less or equal to 64 bytes")
	}

	if len(req.VtpmNonce) > vtpm.Nonce {
		return nil, errors.New("malformed vTPM nonce, expect less or equal to 32 bytes")
	}

	copy(reportData[:], req.TeeNonce)
	copy(nonce[:], req.VtpmNonce)
	return attestationReq{TeeNonce: reportData, VtpmNonce: nonce, AttType: req.Type}, nil
}

func encodeAttestationResponse(_ context.Context, response interface{}) (interface{}, error) {
	res := response.(attestationRes)
	return &agent.AttestationResponse{
		File: res.File,
	}, nil
}

// Algo implements agent.AgentServiceServer.
func (s *grpcServer) Algo(stream agent.AgentService_AlgoServer) error {
	var algoFile, reqFile []byte
	for {
		algoChunk, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return status.Error(codes.Internal, err.Error())
		}
		algoFile = append(algoFile, algoChunk.Algorithm...)
		reqFile = append(reqFile, algoChunk.Requirements...)
	}
	_, res, err := s.algo.ServeGRPC(stream.Context(), &agent.AlgoRequest{Algorithm: algoFile, Requirements: reqFile})
	if err != nil {
		return err
	}
	ar := res.(*agent.AlgoResponse)
	return stream.SendAndClose(ar)
}

// Data implements agent.AgentServiceServer.
func (s *grpcServer) Data(stream agent.AgentService_DataServer) error {
	var dataFile []byte
	var filename string
	for {
		dataChunk, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return status.Error(codes.Internal, err.Error())
		}
		dataFile = append(dataFile, dataChunk.Dataset...)
		filename = dataChunk.Filename
	}
	_, res, err := s.data.ServeGRPC(stream.Context(), &agent.DataRequest{Dataset: dataFile, Filename: filename})
	if err != nil {
		return err
	}
	ar := res.(*agent.DataResponse)
	return stream.SendAndClose(ar)
}

func (s *grpcServer) Result(req *agent.ResultRequest, stream agent.AgentService_ResultServer) error {
	_, res, err := s.result.ServeGRPC(stream.Context(), req)
	if err != nil {
		return err
	}
	rr := res.(*agent.ResultResponse)

	if err := stream.SetHeader(metadata.New(map[string]string{FileSizeKey: fmt.Sprint(len(rr.File))})); err != nil {
		return status.Error(codes.Internal, err.Error())
	}

	resultBuffer := bytes.NewBuffer(rr.File)

	buf := make([]byte, bufferSize)

	for {
		n, err := resultBuffer.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return status.Error(codes.Internal, err.Error())
		}

		if err := stream.Send(&agent.ResultResponse{File: buf[:n]}); err != nil {
			return status.Error(codes.Internal, err.Error())
		}
	}

	return nil
}

func (s *grpcServer) Attestation(req *agent.AttestationRequest, stream agent.AgentService_AttestationServer) error {
	_, res, err := s.attestation.ServeGRPC(stream.Context(), req)
	if err != nil {
		return err
	}
	rr := res.(*agent.AttestationResponse)

	if err := stream.SetHeader(metadata.New(map[string]string{FileSizeKey: fmt.Sprint(len(rr.File))})); err != nil {
		return status.Error(codes.Internal, err.Error())
	}

	attestationBuffer := bytes.NewBuffer(rr.File)

	buf := make([]byte, bufferSize)

	for {
		n, err := attestationBuffer.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return status.Error(codes.Internal, err.Error())
		}

		if err := stream.Send(&agent.AttestationResponse{File: buf[:n]}); err != nil {
			return status.Error(codes.Internal, err.Error())
		}
	}

	return nil
}
