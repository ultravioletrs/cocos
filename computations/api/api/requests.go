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
	token       string
	id          string
	Name        string                 `json:"name,omitempty"`
	Description string                 `json:"description,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

func (req updateReq) validate() error {
	return nil
}
