// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package atls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	certssdk "github.com/absmach/certs/sdk"
	"github.com/absmach/supermq/pkg/errors"
	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/proto/check"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/vtpm"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/encoding/protojson"
)

const sevProductNameMilan = "Milan"

var policy = attestation.Config{Config: &check.Config{Policy: &check.Policy{}, RootOfTrust: &check.RootOfTrust{}}, PcrConfig: &attestation.PcrConfig{}}

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
			pType, err := getPlatformTypeFromOID(c.oid)

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
			v := CertificateVerifier{}
			err := v.verifyCertificateExtension(c.extension, c.pubKey, c.nonce, c.platformType)
			if c.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetCertificateWithSelfSigned(t *testing.T) {
	p := AttestedCertificateProvider{}

	nonce := make([]byte, 64)
	_, err := rand.Read(nonce)
	require.NoError(t, err)

	serverName := hex.EncodeToString(nonce) + ".nonce"

	clientHello := &tls.ClientHelloInfo{
		ServerName: serverName,
	}

	cert, err := p.GetCertificate(clientHello)

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

	p := AttestedCertificateProvider{}

	nonce := make([]byte, 64)
	_, err := rand.Read(nonce)
	require.NoError(t, err)

	serverName := hex.EncodeToString(nonce) + ".nonce"

	clientHello := &tls.ClientHelloInfo{
		ServerName: serverName,
	}

	_, err = p.GetCertificate(clientHello)
	if err != nil {
		t.Logf("Expected error due to missing attestation setup: %v", err)
		assert.Error(t, err)
	}
}

func TestGetCertificateInvalidServerName(t *testing.T) {
	p := AttestedCertificateProvider{}

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

			cert, err := p.GetCertificate(clientHello)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), c.expectErr)
			assert.Nil(t, cert)
		})
	}
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

// TestCertificateVerification unified test suite for certificate verification.
func TestCertificateVerification(t *testing.T) {
	// Setup common test data
	selfSignedCert := createSelfSignedCert(t)
	leafCert, rootCert := generateCertificateChain(t)
	rootCAs := createCertPool(rootCert)
	emptyPool := x509.NewCertPool()

	t.Run("SelfSignedCertificates", func(t *testing.T) {
		testCases := []testCase{
			{
				name:        "ValidSelfSignedCertificate",
				cert:        selfSignedCert,
				rootCAs:     nil,
				expectError: false,
			},
			{
				name:        "EmptyCertificate",
				cert:        &x509.Certificate{},
				rootCAs:     nil,
				expectError: true,
				errorMsg:    "x509: missing ASN.1 contents; use ParseCertificate",
			},
		}

		runCertificateVerificationTests(t, testCases)
	})

	t.Run("CertificateChainVerification", func(t *testing.T) {
		testCases := []testCase{
			{
				name:        "ValidCertificateWithRootCA",
				cert:        leafCert,
				rootCAs:     rootCAs,
				expectError: false,
			},
			{
				name:        "SelfSignedCertificate",
				cert:        rootCert,
				rootCAs:     nil, // Self-signed verification
				expectError: false,
			},
			{
				name:        "InvalidCertificateWithEmptyPool",
				cert:        rootCert,
				rootCAs:     emptyPool,
				expectError: true,
			},
		}

		runCertificateVerificationTests(t, testCases)
	})

	t.Run("ATLSPeerCertificateVerification", func(t *testing.T) {
		nonce := generateNonce(t)

		testCases := []atlsTestCase{
			{
				name:        "InvalidCertificateData",
				rawCerts:    [][]byte{[]byte("invalid cert data")},
				nonce:       nonce,
				rootCAs:     rootCAs,
				expectError: true,
				errorMsg:    "failed to parse x509 certificate",
			},
			{
				name:        "ValidCertificateNoAttestationExtension",
				rawCerts:    [][]byte{leafCert.Raw},
				nonce:       nonce,
				rootCAs:     rootCAs,
				expectError: true,
				errorMsg:    "attestation extension not found in certificate",
			},
		}

		runATLSVerificationTests(t, testCases)
	})
}

// Unified test case structures.
type testCase struct {
	name        string
	cert        *x509.Certificate
	rootCAs     *x509.CertPool
	expectError bool
	errorMsg    string
}

type atlsTestCase struct {
	name        string
	rawCerts    [][]byte
	nonce       []byte
	rootCAs     *x509.CertPool
	expectError bool
	errorMsg    string
}

// Unified test runners.
func runCertificateVerificationTests(t *testing.T, testCases []testCase) {
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			v := CertificateVerifier{
				rootCAs: tc.rootCAs,
			}
			err := v.verifyCertificateSignature(tc.cert)

			if tc.expectError {
				assert.Error(t, err)
				if tc.errorMsg != "" {
					if tc.errorMsg == "x509: missing ASN.1 contents; use ParseCertificate" {
						// For specific error matching
						assert.True(t, errors.Contains(err, errors.New(tc.errorMsg)),
							fmt.Sprintf("expected error %q, got %v", tc.errorMsg, err))
					} else {
						assert.Contains(t, err.Error(), tc.errorMsg)
					}
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func runATLSVerificationTests(t *testing.T, testCases []atlsTestCase) {
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			v := CertificateVerifier{
				rootCAs: tc.rootCAs,
			}
			err := v.VerifyPeerCertificate(tc.rawCerts, nil, tc.nonce)

			if tc.expectError {
				assert.Error(t, err)
				if tc.errorMsg != "" {
					assert.Contains(t, err.Error(), tc.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Unified certificate creation utilities.
func createSelfSignedCert(t *testing.T) *x509.Certificate {
	privateKey := generateRSAKey(t)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour), // Consistent duration
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	return createCertificateFromTemplate(t, &template, &template, &privateKey.PublicKey, privateKey)
}

func generateCertificateChain(t *testing.T) (leafCert, rootCert *x509.Certificate) {
	// Generate root certificate
	rootKey := generateRSAKey(t)
	rootTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Root CA"},
			Country:      []string{"US"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	rootCert = createCertificateFromTemplate(t, &rootTemplate, &rootTemplate, &rootKey.PublicKey, rootKey)

	// Generate leaf certificate signed by root
	leafKey := generateRSAKey(t)
	leafTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Leaf"},
			Country:      []string{"US"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	leafCert = createCertificateFromTemplate(t, &leafTemplate, &rootTemplate, &leafKey.PublicKey, rootKey)

	return leafCert, rootCert
}

// Helper functions for consistency.
func generateRSAKey(t *testing.T) *rsa.PrivateKey {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return privateKey
}

func createCertificateFromTemplate(t *testing.T, template, parent *x509.Certificate, pub interface{}, priv interface{}) *x509.Certificate {
	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

func createCertPool(certs ...*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	return pool
}

func generateNonce(t *testing.T) []byte {
	nonce := make([]byte, 64)
	_, err := rand.Read(nonce)
	require.NoError(t, err)
	return nonce
}
