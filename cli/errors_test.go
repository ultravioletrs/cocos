package cli

import (
	"bytes"
	"errors"
	"testing"

	mgerrors "github.com/absmach/magistrala/pkg/errors"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/ultravioletrs/cocos/agent/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestDecodeErros(t *testing.T) {
	tests := []struct {
		name     string
		input    error
		expected error
	}{
		{
			name:     "Permission Denied",
			input:    status.Error(codes.PermissionDenied, "permission denied"),
			expected: errDigitalSignatureVerificationFailed,
		},
		{
			name:     "Unavailable",
			input:    status.Error(codes.Unavailable, "service unavailable"),
			expected: errAgentUnavailable,
		},
		{
			name:     "Unknown",
			input:    status.Error(codes.Unknown, "unknown error"),
			expected: status.Error(codes.Unknown, "unknown error"),
		},
		{
			name:     "Signature Verification Failed",
			input:    mgerrors.Wrap(auth.ErrSignatureVerificationFailed, errors.New("wrapped error")),
			expected: auth.ErrSignatureVerificationFailed,
		},
		{
			name:     "Other Error",
			input:    errors.New("other error"),
			expected: errors.New("other error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := decodeErros(tt.input)
			if result.Error() != tt.expected.Error() {
				t.Errorf("decodeErros(%v) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestPrintError(t *testing.T) {
	// Save the original color.NoColor value and restore it after the test
	origNoColor := color.NoColor
	color.NoColor = true
	defer func() { color.NoColor = origNoColor }()

	tests := []struct {
		name     string
		message  string
		err      error
		verbose  bool
		expected string
	}{
		{
			name:     "Non-verbose mode",
			message:  "Error: %s",
			err:      status.Error(codes.PermissionDenied, "permission denied"),
			verbose:  false,
			expected: "Error: digital signature verification failed, check the provided public key\n",
		},
		{
			name:     "Verbose mode",
			message:  "Error: %s",
			err:      status.Error(codes.PermissionDenied, "permission denied"),
			verbose:  true,
			expected: "Error: rpc error: code = PermissionDenied desc = permission denied\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Verbose = tt.verbose
			cmd := &cobra.Command{}
			buf := new(bytes.Buffer)
			cmd.SetOut(buf)

			printError(cmd, tt.message, tt.err)

			if got := buf.String(); got != tt.expected {
				t.Errorf("printError() output = %q, want %q", got, tt.expected)
			}
		})
	}
}
