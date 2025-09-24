// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package atls

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/absmach/certs"
	certscli "github.com/absmach/certs/cli"
	certssdk "github.com/absmach/certs/sdk"
	"github.com/absmach/supermq/pkg/errors"
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
	baseURL string
	client  *http.Client
}

type CSRRequest struct {
	CSR string `json:"csr,omitempty"`
}

func NewCAClient(baseURL string) *CAClient {
	return &CAClient{
		baseURL: baseURL,
		client:  &http.Client{},
	}
}

func (c *CAClient) RequestCertificate(csrMetadata certs.CSRMetadata, privateKey *ecdsa.PrivateKey, cvmID, domainId string, ttl time.Duration) ([]byte, error) {
	csr, sdkerr := certscli.CreateCSR(csrMetadata, privateKey)
	if sdkerr != nil {
		return nil, fmt.Errorf("failed to create CSR: %w", sdkerr)
	}

	request := CSRRequest{CSR: string(csr.CSR)}
	requestData, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CSR request: %w", err)
	}

	endpoint := fmt.Sprintf("certs/csrs/%s", cvmID)
	query := url.Values{}
	query.Add("ttl", ttl.String())
	requestURL := fmt.Sprintf("%s/%s?%s", c.baseURL, endpoint, query.Encode())

	_, responseBody, err := c.processRequest(http.MethodPost, requestURL, requestData, nil, http.StatusOK)
	if err != nil {
		return nil, fmt.Errorf("failed to process CA request: %w", err)
	}

	var cert certssdk.Certificate
	if err := json.Unmarshal(responseBody, &cert); err != nil {
		return nil, fmt.Errorf("failed to unmarshal certificate response: %w", err)
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

func (c *CAClient) processRequest(method, reqURL string, data []byte, headers map[string]string, expectedRespCodes ...int) (http.Header, []byte, errors.SDKError) {
	req, err := http.NewRequest(method, reqURL, bytes.NewReader(data))
	if err != nil {
		return make(http.Header), []byte{}, errors.NewSDKError(err)
	}

	req.Header.Add("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Add(key, value)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return make(http.Header), []byte{}, errors.NewSDKError(err)
	}
	defer resp.Body.Close()

	sdkErr := errors.CheckError(resp, expectedRespCodes...)
	if sdkErr != nil {
		return make(http.Header), []byte{}, sdkErr
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return make(http.Header), []byte{}, errors.NewSDKError(err)
	}

	return resp.Header, body, nil
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
