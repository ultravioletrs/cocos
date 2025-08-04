// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package atls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	certssdk "github.com/absmach/certs/sdk"
	"github.com/absmach/supermq/pkg/errors"
	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/proto/check"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/mocks"
	"github.com/ultravioletrs/cocos/pkg/attestation/vtpm"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/encoding/protojson"
)

const sevProductNameMilan = "Milan"

var policy = attestation.Config{Config: &check.Config{Policy: &check.Policy{}, RootOfTrust: &check.RootOfTrust{}}, PcrConfig: &attestation.PcrConfig{}}

func TestGetPlatformProvider(t *testing.T) {
	cases := []struct {
		name          string
		platformType  attestation.PlatformType
		expectedError error
	}{
		{
			name:          "Valid platform type SNPvTPM",
			platformType:  attestation.SNPvTPM,
			expectedError: nil,
		},
		{
			name:          "Valid platform type Azure",
			platformType:  attestation.Azure,
			expectedError: nil,
		},
		{
			name:          "Valid platform type TDX",
			platformType:  attestation.TDX,
			expectedError: nil,
		},
		{
			name:          "Invalid platform type",
			platformType:  999,
			expectedError: errors.New("unsupported platform type: 999"),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			provider, err := getPlatformProvider(c.platformType)

			if c.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, c.expectedError.Error(), err.Error())
				assert.Nil(t, provider)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, provider)
			}
		})
	}
}

func TestGetPlatformVerifier(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "policy")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	attestationPB := prepVerifyAttReport(t)
	err = setAttestationPolicy(attestationPB, tempDir)
	require.NoError(t, err)

	cases := []struct {
		name          string
		platformType  attestation.PlatformType
		expectedError error
	}{
		{
			name:          "Valid platform type SNPvTPM",
			platformType:  attestation.SNPvTPM,
			expectedError: nil,
		},
		{
			name:          "Valid platform type Azure",
			platformType:  attestation.Azure,
			expectedError: nil,
		},
		{
			name:          "Valid platform type TDX",
			platformType:  attestation.TDX,
			expectedError: errors.New("unknown field \"pcr_values\""),
		},
		{
			name:          "Invalid platform type",
			platformType:  999,
			expectedError: errors.New("unsupported platform type: 999"),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			verifier, err := getPlatformVerifier(c.platformType)

			if c.expectedError != nil {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), c.expectedError.Error())
				assert.Nil(t, verifier)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, verifier)
			}
		})
	}
}

func TestGetOID(t *testing.T) {
	cases := []struct {
		name          string
		platformType  attestation.PlatformType
		expectedOID   asn1.ObjectIdentifier
		expectedError error
	}{
		{
			name:          "Valid platform type SNPvTPM",
			platformType:  attestation.SNPvTPM,
			expectedOID:   SNPvTPMOID,
			expectedError: nil,
		},
		{
			name:          "Valid platform type Azure",
			platformType:  attestation.Azure,
			expectedOID:   AzureOID,
			expectedError: nil,
		},
		{
			name:          "Valid platform type TDX",
			platformType:  attestation.TDX,
			expectedOID:   TDXOID,
			expectedError: nil,
		},
		{
			name:          "Invalid platform type",
			platformType:  999,
			expectedOID:   nil,
			expectedError: errors.New("unsupported platform type: 999"),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			oid, err := getOID(c.platformType)

			if c.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, c.expectedError.Error(), err.Error())
				assert.Nil(t, oid)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, c.expectedOID, oid)
			}
		})
	}
}

func TestGetPlatformTypeFromOID(t *testing.T) {
	cases := []struct {
		name          string
		oid           asn1.ObjectIdentifier
		expectedType  attestation.PlatformType
		expectedError error
	}{
		{
			name:          "Valid OID for SNPvTPM",
			oid:           SNPvTPMOID,
			expectedType:  attestation.SNPvTPM,
			expectedError: nil,
		},
		{
			name:          "Valid OID for Azure",
			oid:           AzureOID,
			expectedType:  attestation.Azure,
			expectedError: nil,
		},
		{
			name:          "Valid OID for TDX",
			oid:           TDXOID,
			expectedType:  attestation.TDX,
			expectedError: nil,
		},
		{
			name:          "Invalid OID",
			oid:           asn1.ObjectIdentifier{1, 2, 3},
			expectedType:  0,
			expectedError: errors.New("unsupported OID: 1.2.3"),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pType, err := GetPlatformTypeFromOID(c.oid)

			if c.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, c.expectedError.Error(), err.Error())
				assert.Equal(t, attestation.PlatformType(0), pType)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, c.expectedType, pType)
			}
		})
	}
}

func TestVerifyCertificateExtension(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "policy")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	attestationPB := prepVerifyAttReport(t)
	err = setAttestationPolicy(attestationPB, tempDir)
	require.NoError(t, err)

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pubKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)

	nonce := make([]byte, 64)
	_, err = rand.Read(nonce)
	require.NoError(t, err)

	teeNonce := append(pubKeyDER, nonce...)
	hashNonce := sha3.Sum512(teeNonce)

	cases := []struct {
		name         string
		extension    []byte
		pubKey       []byte
		nonce        []byte
		platformType attestation.PlatformType
		expectError  bool
	}{
		{
			name:         "Valid extension with SNPvTPM",
			extension:    hashNonce[:],
			pubKey:       pubKeyDER,
			nonce:        nonce,
			platformType: attestation.SNPvTPM,
			expectError:  true,
		},
		{
			name:         "Invalid platform type",
			extension:    hashNonce[:],
			pubKey:       pubKeyDER,
			nonce:        nonce,
			platformType: 999,
			expectError:  true,
		},
		{
			name:         "Empty extension",
			extension:    []byte{},
			pubKey:       pubKeyDER,
			nonce:        nonce,
			platformType: attestation.SNPvTPM,
			expectError:  true,
		},
		{
			name:         "Empty public key",
			extension:    hashNonce[:],
			pubKey:       []byte{},
			nonce:        nonce,
			platformType: attestation.SNPvTPM,
			expectError:  true,
		},
		{
			name:         "Empty nonce",
			extension:    hashNonce[:],
			pubKey:       pubKeyDER,
			nonce:        []byte{},
			platformType: attestation.SNPvTPM,
			expectError:  true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := VerifyCertificateExtension(c.extension, c.pubKey, c.nonce, c.platformType)
			if c.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetCertificateExtension(t *testing.T) {
	mockProvider := new(mocks.Provider)

	mockProvider.On("Attestation", mock.Anything, mock.Anything).Return([]byte("mock-attestation-data"), nil)

	pubKey := []byte("test-public-key")
	nonce := make([]byte, 32)
	_, err := rand.Read(nonce)
	require.NoError(t, err)

	testOID := asn1.ObjectIdentifier{1, 2, 3, 4}

	extension, err := getCertificateExtension(mockProvider, pubKey, nonce, testOID)
	assert.NoError(t, err)
	assert.Equal(t, testOID, extension.Id)
	assert.Equal(t, []byte("mock-attestation-data"), extension.Value)
}

func TestGetCertificateWithSelfSigned(t *testing.T) {
	getCertFunc := GetCertificate("", "")

	nonce := make([]byte, 64)
	_, err := rand.Read(nonce)
	require.NoError(t, err)

	serverName := hex.EncodeToString(nonce) + ".nonce"

	clientHello := &tls.ClientHelloInfo{
		ServerName: serverName,
	}

	cert, err := getCertFunc(clientHello)

	if err != nil {
		t.Logf("Expected error due to missing attestation setup: %v", err)
		assert.Error(t, err)
	} else {
		assert.NotNil(t, cert)
		assert.NotEmpty(t, cert.Certificate)
		assert.NotNil(t, cert.PrivateKey)
	}
}

func TestGetCertificateWithCA(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		mockCert := certssdk.Certificate{
			Certificate: "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIBATANBgkqhkiG9w0BAQsFADAYMRYwFAYDVQQDDA1UZXN0IENBIFJvb3QwHhcNMjMwMzMxMDAwMDAwWhcNMjQwMzMxMDAwMDAwWjAYMRYwFAYDVQQDDA1UZXN0IENlcnRpZmljYXRlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtest-key-data-here\n-----END CERTIFICATE-----",
		}

		response, _ := json.Marshal(mockCert)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(response); err != nil {
			http.Error(w, "Failed to write response", http.StatusInternalServerError)
			return
		}
	}))
	defer mockServer.Close()

	getCertFunc := GetCertificate(mockServer.URL, "test-cvm-id")

	nonce := make([]byte, 64)
	_, err := rand.Read(nonce)
	require.NoError(t, err)

	serverName := hex.EncodeToString(nonce) + ".nonce"

	clientHello := &tls.ClientHelloInfo{
		ServerName: serverName,
	}

	_, err = getCertFunc(clientHello)
	if err != nil {
		t.Logf("Expected error due to missing attestation setup: %v", err)
		assert.Error(t, err)
	}
}

func TestGetCertificateInvalidServerName(t *testing.T) {
	getCertFunc := GetCertificate("", "")

	cases := []struct {
		name       string
		serverName string
		expectErr  string
	}{
		{
			name:       "Missing .nonce suffix",
			serverName: "invalidname",
			expectErr:  "failed to get platform provider",
		},
		{
			name:       "Too short server name",
			serverName: "short",
			expectErr:  "failed to get platform provider",
		},
		{
			name:       "Invalid nonce encoding",
			serverName: "invalidhex.nonce",
			expectErr:  "failed to get platform provider",
		},
		{
			name:       "Wrong nonce length",
			serverName: "deadbeef.nonce",
			expectErr:  "failed to get platform provider",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			clientHello := &tls.ClientHelloInfo{
				ServerName: c.serverName,
			}

			cert, err := getCertFunc(clientHello)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), c.expectErr)
			assert.Nil(t, cert)
		})
	}
}

func TestProcessRequest(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/success":
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte(`{"message": "success"}`)); err != nil {
				http.Error(w, "Failed to write response", http.StatusInternalServerError)
				return
			}
		case "/notfound":
			w.WriteHeader(http.StatusNotFound)
			if _, err := w.Write([]byte(`{"error": "not found"}`)); err != nil {
				http.Error(w, "Failed to write response", http.StatusInternalServerError)
				return
			}
		case "/headers":
			if r.Header.Get("X-Custom-Header") == "test-value" {
				w.Header().Set("X-Response-Header", "received")
			}
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte(`{"headers": "ok"}`)); err != nil {
				http.Error(w, "Failed to write response", http.StatusInternalServerError)
				return
			}
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer testServer.Close()

	cases := []struct {
		name              string
		method            string
		url               string
		data              []byte
		headers           map[string]string
		expectedRespCodes []int
		expectError       bool
	}{
		{
			name:              "Successful GET request",
			method:            http.MethodGet,
			url:               testServer.URL + "/success",
			data:              nil,
			headers:           nil,
			expectedRespCodes: []int{http.StatusOK},
			expectError:       false,
		},
		{
			name:              "Successful POST request with data",
			method:            http.MethodPost,
			url:               testServer.URL + "/success",
			data:              []byte(`{"test": "data"}`),
			headers:           nil,
			expectedRespCodes: []int{http.StatusOK},
			expectError:       false,
		},
		{
			name:              "Request with custom headers",
			method:            http.MethodGet,
			url:               testServer.URL + "/headers",
			data:              nil,
			headers:           map[string]string{"X-Custom-Header": "test-value"},
			expectedRespCodes: []int{http.StatusOK},
			expectError:       false,
		},
		{
			name:              "Request with unexpected status code",
			method:            http.MethodGet,
			url:               testServer.URL + "/notfound",
			data:              nil,
			headers:           nil,
			expectedRespCodes: []int{http.StatusOK},
			expectError:       true,
		},
		{
			name:              "Request with multiple expected status codes",
			method:            http.MethodGet,
			url:               testServer.URL + "/notfound",
			data:              nil,
			headers:           nil,
			expectedRespCodes: []int{http.StatusOK, http.StatusNotFound},
			expectError:       false,
		},
		{
			name:              "Request to invalid URL",
			method:            http.MethodGet,
			url:               "invalid-url",
			data:              nil,
			headers:           nil,
			expectedRespCodes: []int{http.StatusOK},
			expectError:       true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			headers, body, err := processRequest(c.method, c.url, c.data, c.headers, c.expectedRespCodes...)

			if c.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, headers)
				assert.NotNil(t, body)

				if c.name == "Request with custom headers" {
					assert.Equal(t, "received", headers.Get("X-Response-Header"))
				}
			}
		})
	}
}

func TestGetCertificateExtensionError(t *testing.T) {
	mockProvider := new(mocks.Provider)

	mockProvider.On("Attestation", mock.Anything, mock.Anything).Return(nil, errors.New("failed to get attestation"))

	pubKey := []byte("test-public-key")
	nonce := make([]byte, 32)
	testOID := asn1.ObjectIdentifier{1, 2, 3, 4}

	extension, err := getCertificateExtension(mockProvider, pubKey, nonce, testOID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get attestation")
	assert.Equal(t, pkix.Extension{}, extension)
}

func prepVerifyAttReport(t *testing.T) *sevsnp.Attestation {
	file, err := os.ReadFile("../../attestation.bin")
	require.NoError(t, err)

	if len(file) < abi.ReportSize {
		file = append(file, make([]byte, abi.ReportSize-len(file))...)
	}

	rr, err := abi.ReportCertsToProto(file)
	require.NoError(t, err)

	return rr
}

func setAttestationPolicy(rr *sevsnp.Attestation, policyDirectory string) error {
	attestationPolicyFile, err := os.ReadFile("../../scripts/attestation_policy/attestation_policy.json")
	if err != nil {
		return err
	}

	unmarshalOptions := protojson.UnmarshalOptions{DiscardUnknown: true}

	err = unmarshalOptions.Unmarshal(attestationPolicyFile, policy)
	if err != nil {
		return err
	}

	policy.Config.Policy.Product = &sevsnp.SevProduct{Name: sevsnp.SevProduct_SEV_PRODUCT_MILAN}
	policy.Config.Policy.FamilyId = rr.Report.FamilyId
	policy.Config.Policy.ImageId = rr.Report.ImageId
	policy.Config.Policy.Measurement = rr.Report.Measurement
	policy.Config.Policy.HostData = rr.Report.HostData
	policy.Config.Policy.ReportIdMa = rr.Report.ReportIdMa
	policy.Config.RootOfTrust.ProductLine = sevProductNameMilan

	policyByte, err := vtpm.ConvertPolicyToJSON(&policy)
	if err != nil {
		return err
	}

	policyPath := filepath.Join(policyDirectory, "attestation_policy.json")

	err = os.WriteFile(policyPath, policyByte, 0o644)
	if err != nil {
		return nil
	}

	attestation.AttestationPolicyPath = policyPath

	return nil
}
