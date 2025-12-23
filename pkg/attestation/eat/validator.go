// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package eat

import (
	"fmt"
	"time"
)

// ValidateEATClaims validates EAT claims against policy.
func ValidateEATClaims(claims *EATClaims, policy *EATValidationPolicy) error {
	if policy == nil {
		return nil // No policy, skip validation
	}

	// Check required claims
	for _, requiredClaim := range policy.RequireClaims {
		switch requiredClaim {
		case "eat_nonce":
			if len(claims.Nonce) == 0 {
				return fmt.Errorf("missing required claim: eat_nonce")
			}
		case "measurements":
			if len(claims.Measurements) == 0 {
				return fmt.Errorf("missing required claim: measurements")
			}
		case "platform_type":
			if claims.PlatformType == "" {
				return fmt.Errorf("missing required claim: platform_type")
			}
		case "ueid":
			if len(claims.UEID) == 0 {
				return fmt.Errorf("missing required claim: ueid")
			}
		}
	}

	// Check token age
	if policy.MaxTokenAgeSeconds > 0 && claims.IssuedAt > 0 {
		tokenAge := time.Since(time.Unix(claims.IssuedAt, 0))
		if tokenAge.Seconds() > float64(policy.MaxTokenAgeSeconds) {
			return fmt.Errorf("token too old: %v seconds (max: %d)", tokenAge.Seconds(), policy.MaxTokenAgeSeconds)
		}
	}

	// Check expiration
	if claims.ExpiresAt > 0 {
		if time.Now().Unix() > claims.ExpiresAt {
			return fmt.Errorf("token expired")
		}
	}

	return nil
}

// EATValidationPolicy contains validation rules for EAT tokens.
type EATValidationPolicy struct {
	RequireEATFormat   bool
	AllowedFormats     []string
	MaxTokenAgeSeconds int
	RequireClaims      []string
	VerifySignature    bool
}
