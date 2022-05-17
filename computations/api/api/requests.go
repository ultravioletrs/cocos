package api

import "github.com/ultravioletrs/cocos/computations"

type createReq struct {
	computation computations.Computation
	token       string
}

func (req createReq) validate() error {
	return req.computation.Validate()
}

type viewReq struct {
	token string
	id    string
}

func (req viewReq) validate() error {
	return nil
}

type listReq struct {
	token string
	meta  computations.PageMetadata
}

func (req listReq) validate() error {
	return nil
}

type updateReq struct {
	computation computations.Computation
	token       string
	id          string
	Name        string
	Description string
	meta        computations.PageMetadata
}

func (req updateReq) validate() error {
	return req.computation.Validate()
}
