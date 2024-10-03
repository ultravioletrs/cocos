// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"github.com/absmach/magistrala/pkg/errors"
	"github.com/ultravioletrs/cocos/agent/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func decodeErros(err error) error {
	statusErr, ok := status.FromError(err)
	if ok {
		switch statusErr.Code() {
		case status.CodePermissionDenied:
			return auth.ErrPermissionDenied
		case codes.PermissionDenied:
			return auth.ErrUnauthenticated
		case codes.Unavailable:
			return auth.ErrUnavailable
		}
	}
	switch {
	case errors.Contains(err, auth.ErrSignatureVerificationFailed):
		return auth.ErrSignatureVerificationFailed

	default:
		return err
	}
}
