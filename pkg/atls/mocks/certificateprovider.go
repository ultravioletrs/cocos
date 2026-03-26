// Code generated manually for tests.
// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package mocks

import (
	"crypto/tls"
	"crypto/x509"

	"github.com/stretchr/testify/mock"
	"github.com/ultravioletrs/cocos/pkg/atls/ea"
)

type CertificateProvider struct {
	mock.Mock
}

func (_m *CertificateProvider) BuildLeafExtensions(st *tls.ConnectionState, req *ea.AuthenticatorRequest, leaf *x509.Certificate) ([]ea.Extension, error) {
	ret := _m.Called(st, req, leaf)

	var r0 []ea.Extension
	var r1 error

	if rf, ok := ret.Get(0).(func(*tls.ConnectionState, *ea.AuthenticatorRequest, *x509.Certificate) ([]ea.Extension, error)); ok {
		return rf(st, req, leaf)
	}
	if ret.Get(0) != nil {
		r0 = ret.Get(0).([]ea.Extension)
	}

	if rf, ok := ret.Get(1).(func(*tls.ConnectionState, *ea.AuthenticatorRequest, *x509.Certificate) error); ok {
		r1 = rf(st, req, leaf)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

func NewCertificateProvider(t interface {
	mock.TestingT
	Cleanup(func())
}) *CertificateProvider {
	mockProvider := &CertificateProvider{}
	mockProvider.Mock.Test(t)

	t.Cleanup(func() {
		mockProvider.AssertExpectations(t)
	})

	return mockProvider
}
