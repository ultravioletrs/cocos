// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package atls

import (
	"crypto/ecdsa"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/absmach/certs"
	"github.com/absmach/certs/sdk"
	certssdk "github.com/absmach/certs/sdk"
)

const (
	defaultNotAfterYears = 1
	nonceLength          = 64
	nonceSuffix          = ".nonce"
)

// Platform-specific OIDs for certificate extensions.
var (
	SNPvTPMOID = asn1.ObjectIdentifier{2, 99999, 1, 0}
	AzureOID   = asn1.ObjectIdentifier{2, 99999, 1, 1}
	TDXOID     = asn1.ObjectIdentifier{2, 99999, 1, 2}
)

// CertificateSubject contains certificate subject information.
type CertificateSubject struct {
	Organization  string
	Country       string
	Province      string
	Locality      string
	StreetAddress string
	PostalCode    string
}

// DefaultCertificateSubject returns the default certificate subject for Ultraviolet.
func DefaultCertificateSubject() CertificateSubject {
	return CertificateSubject{
		Organization:  "Ultraviolet",
		Country:       "Serbia",
		Province:      "",
		Locality:      "Belgrade",
		StreetAddress: "Bulevar Arsenija Carnojevica 103",
		PostalCode:    "11000",
	}
}

// CAClient handles communication with Certificate Authority.
type CAClient struct {
	casdk      sdk.SDK
	agentToken string
}

func NewCAClient(casdk sdk.SDK, agentToken string) *CAClient {
	return &CAClient{
		casdk:      casdk,
		agentToken: agentToken,
	}
}

func (c *CAClient) RequestCertificate(csrMetadata certs.CSRMetadata, privateKey *ecdsa.PrivateKey, cvmID string, ttl time.Duration) ([]byte, error) {
	csr, sdkerr := certssdk.CreateCSR(csrMetadata, privateKey)
	if sdkerr != nil {
		return nil, fmt.Errorf("failed to create CSR: %w", sdkerr)
	}

	cert, err := c.casdk.IssueFromCSRInternal(cvmID, ttl.String(), string(csr.CSR), c.agentToken)
	if err != nil {
		return nil, err
	}

	cleanCertificateString := strings.ReplaceAll(cert.Certificate, "\\n", "\n")
	block, rest := pem.Decode([]byte(cleanCertificateString))

	if len(rest) != 0 {
		return nil, fmt.Errorf("failed to decode certificate PEM: unexpected remaining data")
	}
	if block == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM: no PEM block found")
	}

	return block.Bytes, nil
}

func extractNonceFromSNI(serverName string) ([]byte, error) {
	if len(serverName) < len(nonceSuffix) || !hasNonceSuffix(serverName) {
		return nil, fmt.Errorf("invalid server name: %s", serverName)
	}

	nonceStr := serverName[:len(serverName)-len(nonceSuffix)]
	nonce, err := hex.DecodeString(nonceStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode nonce: %w", err)
	}

	if len(nonce) != nonceLength {
		return nil, fmt.Errorf("invalid nonce length: expected %d bytes, got %d bytes", nonceLength, len(nonce))
	}

	return nonce, nil
}

func hasNonceSuffix(serverName string) bool {
	return len(serverName) >= len(nonceSuffix) &&
		serverName[len(serverName)-len(nonceSuffix):] == nonceSuffix
}
