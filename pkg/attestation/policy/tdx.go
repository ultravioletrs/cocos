// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"github.com/absmach/supermq/pkg/errors"
	ccpb "github.com/google/go-tdx-guest/proto/checkconfig"
	"github.com/ultravioletrs/cocos/pkg/attestation/vtpm"
	"google.golang.org/protobuf/encoding/protojson"
)

var (
	ErrTdxConfigNil = errors.New("tdx policy config is nil")
	ErrDecodeString = errors.New("failed to decode string")
)

type TDXConfig struct {
	SGXVendorID  [16]byte
	MinTdxSvn    [16]byte
	MrSeam       []byte
	TdAttributes [8]byte
	Xfam         [8]byte
	MrTd         []byte
	RTMR         [4][]byte
}

func FetchTDXAttestationPolicy(tdxPolicyConfig *TDXConfig) ([]byte, error) {
	if tdxPolicyConfig == nil {
		return []byte{}, ErrTdxConfigNil
	}

	cfgTdx := &ccpb.Config{
		RootOfTrust: &ccpb.RootOfTrust{},
		Policy:      &ccpb.Policy{HeaderPolicy: &ccpb.HeaderPolicy{}, TdQuoteBodyPolicy: &ccpb.TDQuoteBodyPolicy{}},
	}

	cfgTdx.RootOfTrust.CheckCrl = true
	cfgTdx.RootOfTrust.GetCollateral = true

	cfgTdx.Policy.HeaderPolicy.QeVendorId = tdxPolicyConfig.SGXVendorID[:]
	cfgTdx.Policy.TdQuoteBodyPolicy.MinimumTeeTcbSvn = tdxPolicyConfig.MinTdxSvn[:]

	cfgTdx.Policy.TdQuoteBodyPolicy.MrSeam = tdxPolicyConfig.MrSeam[:]
	cfgTdx.Policy.TdQuoteBodyPolicy.TdAttributes = tdxPolicyConfig.TdAttributes[:]
	cfgTdx.Policy.TdQuoteBodyPolicy.Xfam = tdxPolicyConfig.Xfam[:]
	cfgTdx.Policy.TdQuoteBodyPolicy.MrTd = tdxPolicyConfig.MrTd

	for _, reg := range tdxPolicyConfig.RTMR {
		cfgTdx.Policy.TdQuoteBodyPolicy.Rtmrs = append(cfgTdx.Policy.TdQuoteBodyPolicy.Rtmrs, reg)
	}

	marshaler := protojson.MarshalOptions{
		Multiline: true,
		Indent:    "  ",
	}

	tdxPolicy, err := marshaler.Marshal(cfgTdx)
	if err != nil {
		return []byte{}, errors.Wrap(vtpm.ErrJsonMarshalFailed, err)
	}

	return tdxPolicy, nil
}
