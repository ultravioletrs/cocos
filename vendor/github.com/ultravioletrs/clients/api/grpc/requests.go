package grpc

import (
	"github.com/ultravioletrs/clients/internal/apiutil"
)

// authReq represents authorization request. It contains:
// 1. subject - an action invoker (client)
// 2. object - an entity over which action will be executed (client, group, computation, dataset)
// 3. action - type of action that will be executed (read/write)
type authReq struct {
	Sub string
	Obj string
	Act string
}

func (req authReq) validate() error {
	if req.Sub == "" {
		return apiutil.ErrMissingPolicySub
	}

	if req.Obj == "" {
		return apiutil.ErrMissingPolicyObj
	}

	if req.Act == "" {
		return apiutil.ErrMissingPolicyAct
	}

	return nil
}
