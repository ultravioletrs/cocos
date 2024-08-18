// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

//go:build !embed
// +build !embed

package quoteprovider

import "github.com/google/go-sev-guest/client"

func GetQuoteProvider() (client.QuoteProvider, error) {
	return client.GetQuoteProvider()
}
