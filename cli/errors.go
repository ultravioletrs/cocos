// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"github.com/absmach/magistrala/pkg/errors"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/ultravioletrs/cocos/agent/auth"
	"github.com/ultravioletrs/cocos/pkg/clients/grpc/agent"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	errAgentUnavailable                   = errors.New("agent is unavailable on the current address")
	errDigitalSignatureVerificationFailed = errors.New("digital signature verification failed, check the provided public key")
)

func decodeErros(err error) error {
	statusErr, ok := status.FromError(err)
	if ok {
		switch statusErr.Code() {
		case codes.PermissionDenied:
			return errDigitalSignatureVerificationFailed
		case codes.Unavailable:
			return errAgentUnavailable
		case codes.Unknown:
			return err
		}
	}
	switch {
	case errors.Contains(err, auth.ErrSignatureVerificationFailed):
		return auth.ErrSignatureVerificationFailed

	case errors.Contains(err, agent.ErrAgentServiceUnavailable):
		return agent.ErrAgentServiceUnavailable
	default:
		return err
	}
}

func printError(cmd *cobra.Command, message string, err error) {
	if !Verbose {
		err = decodeErros(err)
	}
	msg := color.New(color.FgRed).Sprintf(message, err)
	cmd.Println(msg)
}
