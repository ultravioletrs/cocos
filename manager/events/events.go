// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package events

import "context"

type Listener interface {
	Listen(ctx context.Context)
}
