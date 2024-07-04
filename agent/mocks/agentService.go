// Code generated by mockery v2.42.3. DO NOT EDIT.

// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package mocks

import (
	context "context"

	agent "github.com/ultravioletrs/cocos/agent"

	grpc "google.golang.org/grpc"

	mock "github.com/stretchr/testify/mock"
)

// AgentServiceClient is an autogenerated mock type for the AgentServiceClient type
type AgentServiceClient struct {
	mock.Mock
	grpc.ClientStream
}

func (m *AgentServiceClient) Send(request *agent.AlgoRequest) error {
	args := m.Called(request)
	return args.Error(0)
}

func (m *AgentServiceClient) Recv() (*agent.AlgoResponse, error) {
	args := m.Called()
	if response, ok := args.Get(0).(*agent.AlgoResponse); ok {
		return response, args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *AgentServiceClient) CloseSend() error {
	args := m.Called()
	return args.Error(0)
}

func (m *AgentServiceClient) CloseAndRecv() (*agent.AlgoResponse, error) {
	args := m.Called()
	if response, ok := args.Get(0).(*agent.AlgoResponse); ok {
		return response, args.Error(1)
	}
	return nil, args.Error(1)
}

// Algo provides a mock function with given fields: ctx, opts
func (_m *AgentServiceClient) Algo(ctx context.Context, opts ...grpc.CallOption) (agent.AgentService_AlgoClient, error) {
	_va := make([]interface{}, len(opts))
	for _i := range opts {
		_va[_i] = opts[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	if len(ret) == 0 {
		panic("no return value specified for Algo")
	}

	var r0 agent.AgentService_AlgoClient
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, ...grpc.CallOption) (agent.AgentService_AlgoClient, error)); ok {
		return rf(ctx, opts...)
	}
	if rf, ok := ret.Get(0).(func(context.Context, ...grpc.CallOption) agent.AgentService_AlgoClient); ok {
		r0 = rf(ctx, opts...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(agent.AgentService_AlgoClient)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, ...grpc.CallOption) error); ok {
		r1 = rf(ctx, opts...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Attestation provides a mock function with given fields: ctx, in, opts
func (_m *AgentServiceClient) Attestation(ctx context.Context, in *agent.AttestationRequest, opts ...grpc.CallOption) (*agent.AttestationResponse, error) {
	_va := make([]interface{}, len(opts))
	for _i := range opts {
		_va[_i] = opts[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx, in)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	if len(ret) == 0 {
		panic("no return value specified for Attestation")
	}

	var r0 *agent.AttestationResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *agent.AttestationRequest, ...grpc.CallOption) (*agent.AttestationResponse, error)); ok {
		return rf(ctx, in, opts...)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *agent.AttestationRequest, ...grpc.CallOption) *agent.AttestationResponse); ok {
		r0 = rf(ctx, in, opts...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*agent.AttestationResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *agent.AttestationRequest, ...grpc.CallOption) error); ok {
		r1 = rf(ctx, in, opts...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Data provides a mock function with given fields: ctx, opts
func (_m *AgentServiceClient) Data(ctx context.Context, opts ...grpc.CallOption) (agent.AgentService_DataClient, error) {
	_va := make([]interface{}, len(opts))
	for _i := range opts {
		_va[_i] = opts[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	if len(ret) == 0 {
		panic("no return value specified for Data")
	}

	var r0 agent.AgentService_DataClient
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, ...grpc.CallOption) (agent.AgentService_DataClient, error)); ok {
		return rf(ctx, opts...)
	}
	if rf, ok := ret.Get(0).(func(context.Context, ...grpc.CallOption) agent.AgentService_DataClient); ok {
		r0 = rf(ctx, opts...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(agent.AgentService_DataClient)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, ...grpc.CallOption) error); ok {
		r1 = rf(ctx, opts...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Result provides a mock function with given fields: ctx, in, opts
func (_m *AgentServiceClient) Result(ctx context.Context, in *agent.ResultRequest, opts ...grpc.CallOption) (*agent.ResultResponse, error) {
	_va := make([]interface{}, len(opts))
	for _i := range opts {
		_va[_i] = opts[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx, in)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	if len(ret) == 0 {
		panic("no return value specified for Result")
	}

	var r0 *agent.ResultResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *agent.ResultRequest, ...grpc.CallOption) (*agent.ResultResponse, error)); ok {
		return rf(ctx, in, opts...)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *agent.ResultRequest, ...grpc.CallOption) *agent.ResultResponse); ok {
		r0 = rf(ctx, in, opts...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*agent.ResultResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *agent.ResultRequest, ...grpc.CallOption) error); ok {
		r1 = rf(ctx, in, opts...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewAgentServiceClient creates a new instance of AgentServiceClient. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewAgentServiceClient(t interface {
	mock.TestingT
	Cleanup(func())
}) *AgentServiceClient {
	mock := &AgentServiceClient{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
