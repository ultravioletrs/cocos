package api

import (
	"github.com/ultravioletrs/cocos/computations"
)

type createReq struct {
	computation computations.Computation
	token       string
}

func (req createReq) validate() error {
	return req.computation.Validate()
}
