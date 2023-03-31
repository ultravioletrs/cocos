// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package http

import "github.com/ultravioletrs/manager/manager"

type apiReq interface {
	validate() error
}

type createDomainReq struct {
	Pool   string `json:"pool"`
	Volume string `json:"volume"`
	Domain string `json:"domain"`
}

func (req createDomainReq) validate() error {
	if req.Pool == "" || req.Volume == "" || req.Domain == "" {
		return manager.ErrMalformedEntity
	}

	return nil
}

var _ apiReq = (*runReq)(nil)

type runReq struct {
	Name               string   `json:"name"`
	Description        string   `json:"description"`
	Owner              string   `json:"owner"`
	Datasets           []string `json:"datasets"`
	Algorithms         []string `json:"algorithms"`
	DatasetProviders   []string `json:"dataset_providers"`
	AlgorithmProviders []string `json:"algorithm_providers"`
	ResultConsumers    []string `json:"result_consumers"`
	TTL                int32    `json:"ttl"`
}

func (req runReq) validate() error {
	if req.Name == "" || req.Owner == "" || len(req.Datasets) == 0 || len(req.Algorithms) == 0 {
		return manager.ErrMalformedEntity
	}

	return nil
}
