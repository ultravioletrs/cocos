package cli

import (
	"github.com/ultravioletrs/agent/pkg/sdk"
)

var cliSDK sdk.SDK

func SetSDK(s sdk.SDK) {
	cliSDK = s
}
