// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	tdxrtmr "github.com/google/go-tdx-guest/rtmr"
)

func main() {
	rtmrIndex := flag.Int("rtmr", 3, "TDX RTMR index to extend; userspace may extend RTMR2 or RTMR3")
	sha384Hex := flag.String("sha384", "", "hex-encoded 48-byte SHA-384 digest")
	flag.Parse()

	if *rtmrIndex != 2 && *rtmrIndex != 3 {
		fmt.Fprintf(os.Stderr, "invalid RTMR index %d: userspace can extend only RTMR2 or RTMR3\n", *rtmrIndex)
		os.Exit(1)
	}

	if *sha384Hex == "" {
		fmt.Fprintln(os.Stderr, "missing required -sha384 digest")
		os.Exit(1)
	}

	digest, err := hex.DecodeString(*sha384Hex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid SHA-384 digest: %v\n", err)
		os.Exit(1)
	}

	if len(digest) != 48 {
		fmt.Fprintf(os.Stderr, "invalid SHA-384 digest length %d: expected 48 bytes\n", len(digest))
		os.Exit(1)
	}

	if err := tdxrtmr.ExtendDigest(*rtmrIndex, digest); err != nil {
		fmt.Fprintf(os.Stderr, "failed to extend RTMR%d: %v\n", *rtmrIndex, err)
		os.Exit(1)
	}

	fmt.Printf("extended RTMR%d\n", *rtmrIndex)
}
