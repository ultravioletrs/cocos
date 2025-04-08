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
	ErrVTpmNonceLength  = errors.New("malformed vTPM nonce, expect less or equal to 32 bytes")
	ErrTokenNonceLength = errors.New("malformed token nonce, expect less or equal to 32 bytes")
)

var _ agent.AgentServiceServer = (*grpcServer)(nil)

type grpcServer struct {
	algo              grpc.Handler
	data              grpc.Handler
	result            grpc.Handler
	attestation       grpc.Handler
	imaMeasurements   grpc.Handler
	attestationResult grpc.Handler
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
		imaMeasurements: grpc.NewServer(
			imaMeasurementsEndpoint(svc),
			decodeIMAMeasurementsRequest,
			encodeIMAMeasurementsResponse,
		),
		attestationResult: grpc.NewServer(
			attestationResultEndpoint(svc),
			decodeAttestationResultRequest,
			encodeAttestationResultResponse,
		),
		imaMeasurements: grpc.NewServer(
			imaMeasurementsEndpoint(svc),
			decodeIMAMeasurementsRequest,
			encodeIMAMeasurementsResponse,
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
	var reportData [quoteprovider.Nonce]byte
	var nonce [vtpm.Nonce]byte

	if len(req.TeeNonce) > quoteprovider.Nonce {
		return nil, ErrTEENonceLength
	}

	if len(req.VtpmNonce) > vtpm.Nonce {
		return nil, ErrVTpmNonceLength
	}

	copy(reportData[:], req.TeeNonce)
	copy(nonce[:], req.VtpmNonce)
	return attestationReq{TeeNonce: reportData, VtpmNonce: nonce, AttType: attestation.PlatformType(req.Type)}, nil
}

func encodeAttestationResponse(_ context.Context, response interface{}) (interface{}, error) {
	res := response.(attestationRes)
	return &agent.AttestationResponse{
		File: res.File,
	}, nil
}

func encodeAttestationResultResponse(_ context.Context, response interface{}) (interface{}, error) {
	res := response.(fetchAttestationResultRes)
	return &agent.AttestationResultResponse{
		File: res.File,
	}, nil
}

func decodeAttestationResultRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(*agent.AttestationResultRequest)
	var nonce [vtpm.Nonce]byte

	if len(req.TokenNonce) > vtpm.Nonce {
		return nil, ErrVTpmNonceLength
	}

	copy(nonce[:], req.TokenNonce)
	return FetchAttestationResultReq{tokenNonce: nonce, AttType: config.AttestationType(req.Type)}, nil
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

func (s *grpcServer) IMAMeasurements(req *agent.IMAMeasurementsRequest, stream agent.AgentService_IMAMeasurementsServer) error {
	_, res, err := s.imaMeasurements.ServeGRPC(stream.Context(), req)
	if err != nil {
		return err
	}
	rr := res.(*agent.IMAMeasurementsResponse)

	if err := stream.SetHeader(metadata.New(map[string]string{FileSizeKey: strconv.Itoa(len(rr.File))})); err != nil {
		return status.Error(codes.Internal, err.Error())
	}

	imaBuff := bytes.NewBuffer(rr.File)
	pcr10Buff := bytes.NewBuffer(rr.Pcr10)

	imaResBuff := make([]byte, bufferSize)
	pcr10ResBuff := make([]byte, bufferSize)

	for {
		nIma, errIma := imaBuff.Read(imaResBuff)
		if errIma != nil && errIma != io.EOF {
			return status.Error(codes.Internal, errIma.Error())
		}

		nPcr, errPcr := pcr10Buff.Read(pcr10ResBuff)
		if errPcr != nil && errPcr != io.EOF {
			return status.Error(codes.Internal, errPcr.Error())
		}

		if nIma == 0 && errIma == io.EOF &&
			nPcr == 0 && errPcr == io.EOF {
			break
		}

		if err := stream.Send(&agent.IMAMeasurementsResponse{File: imaResBuff[:nIma], Pcr10: pcr10ResBuff[:nPcr]}); err != nil {
			return status.Error(codes.Internal, err.Error())
		}
	}

	return nil
}

func (s *grpcServer) AttestationResult(ctx context.Context, req *agent.FetchAttestationResultRequest) (*agent.FetchAttestationResultResponse, error) {
	_, res, err := s.attestationResult.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rr, ok := res.(*agent.AttestationResultResponse)

	if !ok {
		return nil, status.Error(codes.Internal, "failed to cast response to FetchAttestationResultResponse")
	}

	return rr, nil
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

func (s *grpcServer) IMAMeasurements(req *agent.IMAMeasurementsRequest, stream agent.AgentService_IMAMeasurementsServer) error {
	_, res, err := s.imaMeasurements.ServeGRPC(stream.Context(), req)
	if err != nil {
		return err
	}
	rr := res.(*agent.IMAMeasurementsResponse)

	if err := stream.SetHeader(metadata.New(map[string]string{FileSizeKey: strconv.Itoa(len(rr.File))})); err != nil {
		return status.Error(codes.Internal, err.Error())
	}

	imaBuff := bytes.NewBuffer(rr.File)
	pcr10Buff := bytes.NewBuffer(rr.Pcr10)

	imaResBuff := make([]byte, bufferSize)
	pcr10ResBuff := make([]byte, bufferSize)

	for {
		nIma, errIma := imaBuff.Read(imaResBuff)
		if errIma != nil && errIma != io.EOF {
			return status.Error(codes.Internal, errIma.Error())
		}

		nPcr, errPcr := pcr10Buff.Read(pcr10ResBuff)
		if errPcr != nil && errPcr != io.EOF {
			return status.Error(codes.Internal, errPcr.Error())
		}

		if nIma == 0 && errIma == io.EOF &&
			nPcr == 0 && errPcr == io.EOF {
			break
		}

		if err := stream.Send(&agent.IMAMeasurementsResponse{File: imaResBuff[:nIma], Pcr10: pcr10ResBuff[:nPcr]}); err != nil {
			return status.Error(codes.Internal, err.Error())
		}
	}

	return nil
}
