// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.4.0
// - protoc             v5.28.1
// source: agent/agent.proto

package agent

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.62.0 or later.
const _ = grpc.SupportPackageIsVersion8

const (
	AgentService_Algo_FullMethodName        = "/agent.AgentService/Algo"
	AgentService_Data_FullMethodName        = "/agent.AgentService/Data"
	AgentService_Result_FullMethodName      = "/agent.AgentService/Result"
	AgentService_Attestation_FullMethodName = "/agent.AgentService/Attestation"
)

// AgentServiceClient is the client API for AgentService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type AgentServiceClient interface {
	Algo(ctx context.Context, opts ...grpc.CallOption) (AgentService_AlgoClient, error)
	Data(ctx context.Context, opts ...grpc.CallOption) (AgentService_DataClient, error)
	Result(ctx context.Context, in *ResultRequest, opts ...grpc.CallOption) (AgentService_ResultClient, error)
	Attestation(ctx context.Context, in *AttestationRequest, opts ...grpc.CallOption) (AgentService_AttestationClient, error)
}

type agentServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewAgentServiceClient(cc grpc.ClientConnInterface) AgentServiceClient {
	return &agentServiceClient{cc}
}

func (c *agentServiceClient) Algo(ctx context.Context, opts ...grpc.CallOption) (AgentService_AlgoClient, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &AgentService_ServiceDesc.Streams[0], AgentService_Algo_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &agentServiceAlgoClient{ClientStream: stream}
	return x, nil
}

type AgentService_AlgoClient interface {
	Send(*AlgoRequest) error
	CloseAndRecv() (*AlgoResponse, error)
	grpc.ClientStream
}

type agentServiceAlgoClient struct {
	grpc.ClientStream
}

func (x *agentServiceAlgoClient) Send(m *AlgoRequest) error {
	return x.ClientStream.SendMsg(m)
}

func (x *agentServiceAlgoClient) CloseAndRecv() (*AlgoResponse, error) {
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	m := new(AlgoResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *agentServiceClient) Data(ctx context.Context, opts ...grpc.CallOption) (AgentService_DataClient, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &AgentService_ServiceDesc.Streams[1], AgentService_Data_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &agentServiceDataClient{ClientStream: stream}
	return x, nil
}

type AgentService_DataClient interface {
	Send(*DataRequest) error
	CloseAndRecv() (*DataResponse, error)
	grpc.ClientStream
}

type agentServiceDataClient struct {
	grpc.ClientStream
}

func (x *agentServiceDataClient) Send(m *DataRequest) error {
	return x.ClientStream.SendMsg(m)
}

func (x *agentServiceDataClient) CloseAndRecv() (*DataResponse, error) {
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	m := new(DataResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *agentServiceClient) Result(ctx context.Context, in *ResultRequest, opts ...grpc.CallOption) (AgentService_ResultClient, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &AgentService_ServiceDesc.Streams[2], AgentService_Result_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &agentServiceResultClient{ClientStream: stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type AgentService_ResultClient interface {
	Recv() (*ResultResponse, error)
	grpc.ClientStream
}

type agentServiceResultClient struct {
	grpc.ClientStream
}

func (x *agentServiceResultClient) Recv() (*ResultResponse, error) {
	m := new(ResultResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *agentServiceClient) Attestation(ctx context.Context, in *AttestationRequest, opts ...grpc.CallOption) (AgentService_AttestationClient, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &AgentService_ServiceDesc.Streams[3], AgentService_Attestation_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &agentServiceAttestationClient{ClientStream: stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type AgentService_AttestationClient interface {
	Recv() (*AttestationResponse, error)
	grpc.ClientStream
}

type agentServiceAttestationClient struct {
	grpc.ClientStream
}

func (x *agentServiceAttestationClient) Recv() (*AttestationResponse, error) {
	m := new(AttestationResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// AgentServiceServer is the server API for AgentService service.
// All implementations must embed UnimplementedAgentServiceServer
// for forward compatibility
type AgentServiceServer interface {
	Algo(AgentService_AlgoServer) error
	Data(AgentService_DataServer) error
	Result(*ResultRequest, AgentService_ResultServer) error
	Attestation(*AttestationRequest, AgentService_AttestationServer) error
	mustEmbedUnimplementedAgentServiceServer()
}

// UnimplementedAgentServiceServer must be embedded to have forward compatible implementations.
type UnimplementedAgentServiceServer struct {
}

func (UnimplementedAgentServiceServer) Algo(AgentService_AlgoServer) error {
	return status.Errorf(codes.Unimplemented, "method Algo not implemented")
}
func (UnimplementedAgentServiceServer) Data(AgentService_DataServer) error {
	return status.Errorf(codes.Unimplemented, "method Data not implemented")
}
func (UnimplementedAgentServiceServer) Result(*ResultRequest, AgentService_ResultServer) error {
	return status.Errorf(codes.Unimplemented, "method Result not implemented")
}
func (UnimplementedAgentServiceServer) Attestation(*AttestationRequest, AgentService_AttestationServer) error {
	return status.Errorf(codes.Unimplemented, "method Attestation not implemented")
}
func (UnimplementedAgentServiceServer) mustEmbedUnimplementedAgentServiceServer() {}

// UnsafeAgentServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to AgentServiceServer will
// result in compilation errors.
type UnsafeAgentServiceServer interface {
	mustEmbedUnimplementedAgentServiceServer()
}

func RegisterAgentServiceServer(s grpc.ServiceRegistrar, srv AgentServiceServer) {
	s.RegisterService(&AgentService_ServiceDesc, srv)
}

func _AgentService_Algo_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(AgentServiceServer).Algo(&agentServiceAlgoServer{ServerStream: stream})
}

type AgentService_AlgoServer interface {
	SendAndClose(*AlgoResponse) error
	Recv() (*AlgoRequest, error)
	grpc.ServerStream
}

type agentServiceAlgoServer struct {
	grpc.ServerStream
}

func (x *agentServiceAlgoServer) SendAndClose(m *AlgoResponse) error {
	return x.ServerStream.SendMsg(m)
}

func (x *agentServiceAlgoServer) Recv() (*AlgoRequest, error) {
	m := new(AlgoRequest)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _AgentService_Data_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(AgentServiceServer).Data(&agentServiceDataServer{ServerStream: stream})
}

type AgentService_DataServer interface {
	SendAndClose(*DataResponse) error
	Recv() (*DataRequest, error)
	grpc.ServerStream
}

type agentServiceDataServer struct {
	grpc.ServerStream
}

func (x *agentServiceDataServer) SendAndClose(m *DataResponse) error {
	return x.ServerStream.SendMsg(m)
}

func (x *agentServiceDataServer) Recv() (*DataRequest, error) {
	m := new(DataRequest)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _AgentService_Result_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(ResultRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(AgentServiceServer).Result(m, &agentServiceResultServer{ServerStream: stream})
}

type AgentService_ResultServer interface {
	Send(*ResultResponse) error
	grpc.ServerStream
}

type agentServiceResultServer struct {
	grpc.ServerStream
}

func (x *agentServiceResultServer) Send(m *ResultResponse) error {
	return x.ServerStream.SendMsg(m)
}

func _AgentService_Attestation_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(AttestationRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(AgentServiceServer).Attestation(m, &agentServiceAttestationServer{ServerStream: stream})
}

type AgentService_AttestationServer interface {
	Send(*AttestationResponse) error
	grpc.ServerStream
}

type agentServiceAttestationServer struct {
	grpc.ServerStream
}

func (x *agentServiceAttestationServer) Send(m *AttestationResponse) error {
	return x.ServerStream.SendMsg(m)
}

// AgentService_ServiceDesc is the grpc.ServiceDesc for AgentService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var AgentService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "agent.AgentService",
	HandlerType: (*AgentServiceServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "Algo",
			Handler:       _AgentService_Algo_Handler,
			ClientStreams: true,
		},
		{
			StreamName:    "Data",
			Handler:       _AgentService_Data_Handler,
			ClientStreams: true,
		},
		{
			StreamName:    "Result",
			Handler:       _AgentService_Result_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "Attestation",
			Handler:       _AgentService_Attestation_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "agent/agent.proto",
}
