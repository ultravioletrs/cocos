// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package apiutil

import "github.com/mainflux/mainflux/pkg/errors"

// Errors defined in this file are used by the LoggingErrorEncoder decorator
// to distinguish and log API request validation errors and avoid that service
// errors are logged twice.
var (
	// ErrBearerToken indicates missing or invalid bearer user token.
	ErrBearerToken = errors.New("missing or invalid bearer user token")

	// ErrBearerKey indicates missing or invalid bearer entity key.
	ErrBearerKey = errors.New("missing or invalid bearer entity key")

	// ErrMissingIdentity indicates missing entity Identity.
	ErrMissingIdentity = errors.New("missing entity identity")

	// ErrMissingID indicates missing entity ID.
	ErrMissingID = errors.New("missing entity id")

	// ErrInvalidAuthKey indicates invalid auth key.
	ErrInvalidAuthKey = errors.New("invalid auth key")

	// ErrInvalidIDFormat indicates an invalid ID format.
	ErrInvalidIDFormat = errors.New("invalid id format provided")

	// ErrNameSize indicates that name size exceeds the max.
	ErrNameSize = errors.New("invalid name size")

	// ErrEmailSize indicates that email size exceeds the max.
	ErrEmailSize = errors.New("invalid email size")

	// ErrLimitSize indicates that an invalid limit.
	ErrLimitSize = errors.New("invalid limit size")

	// ErrOffsetSize indicates an invalid offset.
	ErrOffsetSize = errors.New("invalid offset size")

	// ErrInvalidOrder indicates an invalid list order.
	ErrInvalidOrder = errors.New("invalid list order provided")

	// ErrInvalidDirection indicates an invalid list direction.
	ErrInvalidDirection = errors.New("invalid list direction provided")

	// ErrEmptyList indicates that entity data is empty.
	ErrEmptyList = errors.New("empty list provided")

	// ErrMalformedPolicy indicates that policies are malformed.
	ErrMalformedPolicy = errors.New("malformed policy")

	// ErrMissingPolicyOwner indicated malformed policy owner
	ErrMissingPolicyOwner = errors.New("malformed policy owner")

	// ErrMissingPolicySub indicates malformed policy subject.
	ErrMissingPolicySub = errors.New("malformed policy subject")

	// ErrMissingPolicyObj indicates malformed policies object.
	ErrMissingPolicyObj = errors.New("malformed policy object")

	// ErrMissingPolicyAct indicates malformed policies action.
	ErrMissingPolicyAct = errors.New("malformed policy action")

	// ErrHigherPolicyRank indicates that policies is not the same ranking with parsed policy.
	ErrHigherPolicyRank = errors.New("policy is of a higher rank that of the user")

	// ErrMissingCertData indicates missing cert data (ttl, key_type or key_bits).
	ErrMissingCertData = errors.New("missing certificate data")

	// ErrInvalidTopic indicates an invalid subscription topic.
	ErrInvalidTopic = errors.New("invalid Subscription topic")

	// ErrInvalidContact indicates an invalid subscription contract.
	ErrInvalidContact = errors.New("invalid Subscription contact")

	// ErrMissingName indicates missing identity name.
	ErrMissingName = errors.New("missing identity name")

	// ErrMissingEmail indicates missing email.
	ErrMissingEmail = errors.New("missing email")

	// ErrMissingHost indicates missing host.
	ErrMissingHost = errors.New("missing host")

	// ErrMissingPass indicates missing password.
	ErrMissingPass = errors.New("missing password")

	// ErrMissingConfPass indicates missing conf password.
	ErrMissingConfPass = errors.New("missing conf password")

	// ErrInvalidResetPass indicates an invalid reset password.
	ErrInvalidResetPass = errors.New("invalid reset password")

	// ErrInvalidComparator indicates an invalid comparator.
	ErrInvalidComparator = errors.New("invalid comparator")

	// ErrMissingMemberType indicates missing group member type.
	ErrMissingMemberType = errors.New("missing group member type")

	// ErrInvalidAPIKey indicates an invalid API key type.
	ErrInvalidAPIKey = errors.New("invalid api key type")

	// ErrInvalidLevel indicates an invalid group level.
	ErrInvalidLevel = errors.New("invalid group level (should be between 0 and 5)")

	// ErrBootstrapState indicates an invalid boostrap state.
	ErrBootstrapState = errors.New("invalid bootstrap state")
)
