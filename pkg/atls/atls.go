// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package atls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/absmach/certs"
	certscli "github.com/absmach/certs/cli"
	"github.com/absmach/certs/errors"
	"github.com/absmach/certs/sdk"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/azure"
	"github.com/ultravioletrs/cocos/pkg/attestation/tdx"
	"github.com/ultravioletrs/cocos/pkg/attestation/vtpm"
	"golang.org/x/crypto/sha3"
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

func getPlatformProvider(platformType attestation.PlatformType) (attestation.Provider, error) {
	switch platformType {
	case attestation.SNPvTPM:
		return vtpm.NewProvider(true, vmpl2), nil
	case attestation.Azure:
		return azure.NewProvider(), nil
	case attestation.TDX:
		return tdx.NewProvider(), nil
	default:
		return nil, fmt.Errorf("unsupported platform type: %d", platformType)
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

	var cert sdk.Certificate
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

func GetCertificate(caSDK sdk.SDK, cvmId, domainId string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	pType := attestation.CCPlatform()

	provider, err := getPlatformProvider(pType)
	if err != nil {
		return func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return nil, fmt.Errorf("failed to get platform provider: %w", err)
		}
	}

	teeOid, err := getOID(pType)
	if err != nil {
		return func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return nil, fmt.Errorf("failed to get OID for platform type: %w", err)
		}
	}

	return func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		curve := elliptic.P256()

		privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate private/public key: %w", err)
		}

		pubKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal public key to DER format: %w", err)
		}

		sniLength := len(clientHello.ServerName)
		if sniLength < 7 || clientHello.ServerName[sniLength-6:] != ".nonce" {
			return nil, fmt.Errorf("invalid server name: %s", clientHello.ServerName)
		}

		nonceStr := clientHello.ServerName[:sniLength-6]
		nonce, err := hex.DecodeString(nonceStr)
		if err != nil {
			return nil, fmt.Errorf("failed to decode nonce from server name: %w", err)
		}

		if len(nonce) != 64 {
			return nil, fmt.Errorf("invalid nonce length: expected 64 bytes, got %d bytes", len(nonce))
		}

		attestExtension, err := getCertificateExtension(provider, pubKeyDER, nonce, teeOid)
		if err != nil {
			return nil, fmt.Errorf("failed to get certificate extension: %w", err)
		}

		var certDERBytes []byte

		if caSDK == nil && cvmId == "" {
			certTemplate := &x509.Certificate{
				SerialNumber: big.NewInt(202403311),
				Subject: pkix.Name{
					Organization:  []string{organization},
					Country:       []string{country},
					Province:      []string{province},
					Locality:      []string{locality},
					StreetAddress: []string{streetAddress},
					PostalCode:    []string{postalCode},
				},
				NotBefore:             time.Now(),
				NotAfter:              time.Now().AddDate(notAfterYear, notAfterMonth, notAfterDay),
				KeyUsage:              x509.KeyUsageDigitalSignature,
				ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				BasicConstraintsValid: true,
				ExtraExtensions:       []pkix.Extension{attestExtension},
			}

			DERBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &privateKey.PublicKey, privateKey)
			if err != nil {
				return nil, fmt.Errorf("failed to create certificate: %w", err)
			}

			certDERBytes = DERBytes
		} else {
			csrmd := certs.CSRMetadata{
				Organization:    []string{organization},
				Country:         []string{country},
				Province:        []string{province},
				Locality:        []string{locality},
				StreetAddress:   []string{streetAddress},
				PostalCode:      []string{postalCode},
				ExtraExtensions: []pkix.Extension{attestExtension},
			}

			csr, err := certscli.CreateCSR(csrmd, privateKey)
			if err != nil {
				return nil, fmt.Errorf("failed to create CSR: %w", err)
			}

			notBefore := time.Now()
			notAfter := time.Now().AddDate(notAfterYear, notAfterMonth, notAfterDay)
			ttlString := notAfter.Sub(notBefore).String()

			cert, err := caSDK.IssueFromCSR(cvmId, ttlString, string(csr.CSR))
			if err != nil {
				return nil, err
			}

			cleanCertificateString := strings.ReplaceAll(cert.Certificate, "\\n", "\n")

			block, rest := pem.Decode([]byte(cleanCertificateString))

			if len(rest) != 0 {
				return nil, fmt.Errorf("failed to convert generated certificate to DER format: %s", cleanCertificateString)
			}

			certDERBytes = block.Bytes
		}

		return &tls.Certificate{
			Certificate: [][]byte{certDERBytes},
			PrivateKey:  privateKey,
		}, nil
	}
}

func getCertificateExtension(provider attestation.Provider, pubKey []byte, nonce []byte, teeOid asn1.ObjectIdentifier) (pkix.Extension, error) {
	teeNonce := append(pubKey, nonce...)
	hashNonce := sha3.Sum512(teeNonce)

	rawAttestation, err := provider.Attestation(hashNonce[:], hashNonce[:vtpm.Nonce])
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("failed to get attestation: %w", err)
	}

	return pkix.Extension{
		Id:    teeOid,
		Value: rawAttestation,
	}, nil
}

func processRequest(method, reqUrl string, data []byte, headers map[string]string, expectedRespCodes ...int) (http.Header, []byte, errors.SDKError) {
	req, err := http.NewRequest(method, reqUrl, bytes.NewReader(data))
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
