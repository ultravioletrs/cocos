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
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	certssdk "github.com/absmach/certs/sdk"
	sdkmocks "github.com/absmach/certs/sdk/mocks"
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

const (
	sevProductNameMilan = "Milan"
	testCertPEM = "-----BEGIN CERTIFICATE-----\\nMIIC/zCCAeegAwIBAgIUSuwXMW/DOBN3IAOC1L88B8zdelYwDQYJKoZIhvcNAQEL\\nBQAwDzENMAsGA1UEAwwEdGVzdDAeFw0yNTA5MjkwOTM2MDNaFw0yNjA5MjkwOTM2\\nMDNaMA8xDTALBgNVBAMMBHRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\\nAoIBAQDCl11hfsL3Co7zvb/vkLpuO6qEsvg+jl/PB+qo7b9uHyoP+HJgnaQbEU7X\\nJAFsT1tAoOmI+oO5IRe6GWi+RyeEUsTfl0hsqprawBO5XL0izWfGD+kyemeBdse0\\n3Bzf43HROjj88+hhXzGv62CiZ36QznBCANeJnKzsB+hBZYZcEZ99cTF9nZBH3Q9G\\nGx0VvS6xd1K6aZeQfq0Te8CTLCJJEXJ2gTEtWrHvCMbtBGNE3sJ/R2QSK/VwQ2YZ\\nlci9RrI+P3a8vpTJzU4HTtFjRVNv8MA53gwYXYx81/nrl+t+3eZXXO6UUAaqcUYb\\nrzbRqrwz+WWE2nRB92LRnSa9+BgLAgMBAAGjUzBRMB0GA1UdDgQWBBTvanMP2nw9\\nr7W/O325k68/eYJ+LjAfBgNVHSMEGDAWgBTvanMP2nw9r7W/O325k68/eYJ+LjAP\\nBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCEL6SuGZFRumsuq1Pp\\n4gkYbL6iqaevvdxVJ7uFUr2nn91PLjaDZ/AatuNmmCkwT60eiQWpKdV+cs1hfwYf\\nLTujygsgcePnC9aN5z6LLUB+mfPydz0+pztJHhuAR0kfiaza2Je4xkiKiNe3hmjU\\nIl4V01Ahgb0sR7bCj/DVP0SLcFdYm9ooQjF2WPIr8eGY9ctOpN8z20t1hbuL64TK\\n4ZCOFX6RhqHpJBm2X3Q7Gqk8ClEx914Mnt9LW/ONYeqKIp2J/UV+HgK+iBFb9WHk\\nVYS4ka/Vq5+KqfTcSDormyh2rYVv/7X1Ipjx4eWvUEEZDZx5Lhxi19E56p6ly6m5\\neY1b\\n-----END CERTIFICATE-----"
)

var policy = attestation.Config{Config: &check.Config{Policy: &check.Policy{}, RootOfTrust: &check.RootOfTrust{}}, PcrConfig: &attestation.PcrConfig{}}

// TestCertificateSubject tests the CertificateSubject functionality.
func TestDefaultCertificateSubject(t *testing.T) {
	subject := DefaultCertificateSubject()

	assert.Equal(t, "Ultraviolet", subject.Organization)
	assert.Equal(t, "Serbia", subject.Country)
	assert.Equal(t, "", subject.Province)
	assert.Equal(t, "Belgrade", subject.Locality)
	assert.Equal(t, "Bulevar Arsenija Carnojevica 103", subject.StreetAddress)
	assert.Equal(t, "11000", subject.PostalCode)
}

// TestUnifiedCertificateGenerator tests the unified certificate generator.
func TestUnifiedCertificateGenerator(t *testing.T) {
	t.Run("SelfSignedGenerator", func(t *testing.T) {
		generator, err := NewProvider(nil, attestation.SNPvTPM, "", "", nil)
		assert.NoError(t, err)
		assert.NotNil(t, generator)
	})

	t.Run("CASignedGenerator", func(t *testing.T) {
		mockSDK := sdkmocks.NewSDK(t)

		generator, err := NewProvider(nil, attestation.SNPvTPM, "test-token", "test-cvm-id", mockSDK)
		assert.NoError(t, err)
		assert.NotNil(t, generator)
	})
}

// TestPlatformAttestationProvider tests the platform attestation provider.
func TestPlatformAttestationProvider(t *testing.T) {
	mockProvider := new(mocks.Provider)

	t.Run("NewAttestationProvider", func(t *testing.T) {
		cases := []struct {
			name         string
			platformType attestation.PlatformType
			expectError  bool
		}{
			{"SNPvTPM", attestation.SNPvTPM, false},
			{"Azure", attestation.Azure, false},
			{"TDX", attestation.TDX, false},
			{"Invalid", attestation.PlatformType(999), true},
		}

		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				provider, err := NewAttestationProvider(mockProvider, c.platformType)

				if c.expectError {
					assert.Error(t, err)
					assert.Nil(t, provider)
				} else {
					assert.NoError(t, err)
					assert.NotNil(t, provider)
					assert.Equal(t, c.platformType, provider.PlatformType())
				}
			})
		}
	})

	t.Run("GetAttestation", func(t *testing.T) {
		expectedAttestation := []byte("test-attestation")
		mockProvider.On("Attestation", mock.Anything, mock.Anything).Return(expectedAttestation, nil)

		provider, err := NewAttestationProvider(mockProvider, attestation.SNPvTPM)
		require.NoError(t, err)

		pubKey := []byte("test-pubkey")
		nonce := []byte("test-nonce")

		attestation, err := provider.Attest(pubKey, nonce)

		assert.NoError(t, err)
		assert.Equal(t, expectedAttestation, attestation)
		mockProvider.AssertExpectations(t)
	})

	t.Run("GetAttestationError", func(t *testing.T) {
		mockProvider := new(mocks.Provider)
		mockProvider.On("Attestation", mock.Anything, mock.Anything).Return(nil, errors.New("attestation failed"))

		provider, err := NewAttestationProvider(mockProvider, attestation.SNPvTPM)
		require.NoError(t, err)

		_, err = provider.Attest([]byte("pubkey"), []byte("nonce"))
		assert.Error(t, err)
	})
}

// TestAttestedCertificateProvider tests the attested certificate provider.
func TestAttestedCertificateProvider(t *testing.T) {
	mockProvider := new(mocks.Provider)

	t.Run("GetCertificateSuccess", func(t *testing.T) {
		mockProvider.On("Attestation", mock.Anything, mock.Anything).Return([]byte("test-attestation"), nil)

		attestationProvider, err := NewAttestationProvider(mockProvider, attestation.SNPvTPM)
		require.NoError(t, err)

		subject := DefaultCertificateSubject()

		provider := NewAttestedProvider(attestationProvider, subject)

		// Create valid client hello with nonce
		nonce := make([]byte, 64)
		_, err = rand.Read(nonce)
		require.NoError(t, err)

		serverName := hex.EncodeToString(nonce) + ".nonce"
		clientHello := &tls.ClientHelloInfo{ServerName: serverName}

		cert, err := provider.GetCertificate(clientHello)

		assert.NoError(t, err)
		assert.NotNil(t, cert)
		assert.NotEmpty(t, cert.Certificate)
		assert.NotNil(t, cert.PrivateKey)
	})

	t.Run("InvalidServerName", func(t *testing.T) {
		mockProvider := new(mocks.Provider)
		attestationProvider, err := NewAttestationProvider(mockProvider, attestation.SNPvTPM)
		require.NoError(t, err)

		provider := NewAttestedProvider(attestationProvider, DefaultCertificateSubject())

		clientHello := &tls.ClientHelloInfo{ServerName: "invalid-server-name"}

		_, err = provider.GetCertificate(clientHello)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to extract nonce")
	})

	t.Run("AttestationError", func(t *testing.T) {
		mockProvider := new(mocks.Provider)
		mockProvider.On("Attestation", mock.Anything, mock.Anything).Return(nil, errors.New("attestation failed"))

		attestationProvider, err := NewAttestationProvider(mockProvider, attestation.SNPvTPM)
		require.NoError(t, err)

		provider := NewAttestedProvider(attestationProvider, DefaultCertificateSubject())

		nonce := make([]byte, 64)
		_, err = rand.Read(nonce)
		require.NoError(t, err)

		serverName := hex.EncodeToString(nonce) + ".nonce"
		clientHello := &tls.ClientHelloInfo{ServerName: serverName}

		_, err = provider.GetCertificate(clientHello)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get attestation")
	})
}

// TestNewProvider tests the factory function.
func TestNewProvider(t *testing.T) {
	mockProvider := new(mocks.Provider)

	t.Run("SelfSignedProvider", func(t *testing.T) {
		provider, err := NewProvider(mockProvider, attestation.SNPvTPM, "", "", nil)
		assert.NoError(t, err)
		assert.NotNil(t, provider)
	})

	t.Run("CASignedProviderWithSDK", func(t *testing.T) {
		mockSDK := sdkmocks.NewSDK(t)

		provider, err := NewProvider(mockProvider, attestation.SNPvTPM, "test-token", "test-cvm-id", mockSDK)
		assert.NoError(t, err)
		assert.NotNil(t, provider)
	})

	t.Run("SelfSignedProviderNilSDK", func(t *testing.T) {
		provider, err := NewProvider(mockProvider, attestation.SNPvTPM, "test-token", "test-cvm-id", nil)
		assert.NoError(t, err)
		assert.NotNil(t, provider)
	})

	t.Run("InvalidPlatformType", func(t *testing.T) {
		_, err := NewProvider(mockProvider, attestation.PlatformType(999), "", "", nil)
		assert.Error(t, err)
	})
}

// TestCertificateVerifier tests certificate verification.
func TestCertificateVerifier(t *testing.T) {
	// Setup test policy
	tempDir, err := os.MkdirTemp("", "policy")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	attestationPB := prepVerifyAttReport(t)
	err = setAttestationPolicy(attestationPB, tempDir)
	require.NoError(t, err)

	t.Run("NewCertificateVerifier", func(t *testing.T) {
		rootCAs := x509.NewCertPool()
		verifier := certificateVerifier{rootCAs: rootCAs}

		assert.Equal(t, rootCAs, verifier.rootCAs)
	})

	t.Run("VerifyPeerCertificateNoCertificates", func(t *testing.T) {
		verifier := NewCertificateVerifier(nil)
		err := verifier.VerifyPeerCertificate([][]byte{}, nil, []byte("nonce"))

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no certificates provided")
	})

	t.Run("VerifyPeerCertificateInvalidCert", func(t *testing.T) {
		verifier := NewCertificateVerifier(nil)
		err := verifier.VerifyPeerCertificate([][]byte{[]byte("invalid")}, nil, []byte("nonce"))

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse x509 certificate")
	})

	t.Run("VerifyPeerCertificateNoAttestationExtension", func(t *testing.T) {
		cert := createSelfSignedCert(t)
		verifier := NewCertificateVerifier(nil)

		err := verifier.VerifyPeerCertificate([][]byte{cert.Raw}, nil, []byte("nonce"))

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "attestation extension not found")
	})
}

// TestExtractNonceFromSNI tests nonce extraction from SNI.
func TestExtractNonceFromSNI(t *testing.T) {
	t.Run("ValidNonce", func(t *testing.T) {
		nonce := make([]byte, 64)
		_, err := rand.Read(nonce)
		require.NoError(t, err)

		serverName := hex.EncodeToString(nonce) + ".nonce"

		extractedNonce, err := extractNonceFromSNI(serverName)

		assert.NoError(t, err)
		assert.Equal(t, nonce, extractedNonce)
	})

	t.Run("InvalidServerName", func(t *testing.T) {
		_, err := extractNonceFromSNI("invalid-server-name")
		assert.Error(t, err)
	})

	t.Run("InvalidNonceLength", func(t *testing.T) {
		shortNonce := make([]byte, 32) // Too short
		serverName := hex.EncodeToString(shortNonce) + ".nonce"

		_, err := extractNonceFromSNI(serverName)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid nonce length")
	})

	t.Run("InvalidHexEncoding", func(t *testing.T) {
		serverName := "invalid-hex-encoding.nonce"

		_, err := extractNonceFromSNI(serverName)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode nonce")
	})

	t.Run("MissingNonceSuffix", func(t *testing.T) {
		nonce := make([]byte, 64)
		_, err := rand.Read(nonce)
		require.NoError(t, err)

		serverName := hex.EncodeToString(nonce) + ".invalid"

		_, err = extractNonceFromSNI(serverName)
		assert.Error(t, err)
	})
}

// TestHasNonceSuffix tests the nonce suffix checking.
func TestHasNonceSuffix(t *testing.T) {
	t.Run("ValidSuffix", func(t *testing.T) {
		assert.True(t, hasNonceSuffix("test.nonce"))
	})

	t.Run("InvalidSuffix", func(t *testing.T) {
		assert.False(t, hasNonceSuffix("test.invalid"))
	})

	t.Run("TooShort", func(t *testing.T) {
		assert.False(t, hasNonceSuffix(".non"))
	})

	t.Run("EmptyString", func(t *testing.T) {
		assert.False(t, hasNonceSuffix(""))
	})
}

// TestOIDFunctions tests OID-related functions.
func TestPlatformVerifier(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "policy")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	attestationPB := prepVerifyAttReport(t)
	err = setAttestationPolicy(attestationPB, tempDir)
	require.NoError(t, err)

	cases := []struct {
		name          string
		platformType  attestation.PlatformType
		expectedError bool
	}{
		{"SNPvTPM", attestation.SNPvTPM, false},
		{"Azure", attestation.Azure, false},
		{"TDX", attestation.TDX, true}, // Expected error due to policy format
		{"Invalid", attestation.PlatformType(999), true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			verifier, err := platformVerifier(c.platformType)

			if c.expectedError {
				assert.Error(t, err)
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
		expectedError bool
	}{
		{"SNPvTPM", attestation.SNPvTPM, SNPvTPMOID, false},
		{"Azure", attestation.Azure, AzureOID, false},
		{"TDX", attestation.TDX, TDXOID, false},
		{"Invalid", attestation.PlatformType(999), nil, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			oid, err := OID(c.platformType)

			if c.expectedError {
				assert.Error(t, err)
				assert.Nil(t, oid)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, c.expectedOID, oid)
			}
		})
	}
}

func TestPlatformTypeFromOID(t *testing.T) {
	cases := []struct {
		name          string
		oid           asn1.ObjectIdentifier
		expectedType  attestation.PlatformType
		expectedError bool
	}{
		{"SNPvTPM", SNPvTPMOID, attestation.SNPvTPM, false},
		{"Azure", AzureOID, attestation.Azure, false},
		{"TDX", TDXOID, attestation.TDX, false},
		{"Invalid", asn1.ObjectIdentifier{1, 2, 3}, attestation.PlatformType(0), true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pType, err := platformTypeFromOID(c.oid)

			if c.expectedError {
				assert.Error(t, err)
				assert.Equal(t, attestation.PlatformType(0), pType)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, c.expectedType, pType)
			}
		})
	}
}

// TestVerifyCertificateExtension tests certificate extension verification.
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
			name:         "ValidExtensionSNPvTPM",
			extension:    hashNonce[:],
			pubKey:       pubKeyDER,
			nonce:        nonce,
			platformType: attestation.SNPvTPM,
			expectError:  true, // Expected due to invalid attestation data
		},
		{
			name:         "InvalidPlatformType",
			extension:    hashNonce[:],
			pubKey:       pubKeyDER,
			nonce:        nonce,
			platformType: attestation.PlatformType(999),
			expectError:  true,
		},
		{
			name:         "EmptyExtension",
			extension:    []byte{},
			pubKey:       pubKeyDER,
			nonce:        nonce,
			platformType: attestation.SNPvTPM,
			expectError:  true,
		},
		{
			name:         "EmptyPublicKey",
			extension:    hashNonce[:],
			pubKey:       []byte{},
			nonce:        nonce,
			platformType: attestation.SNPvTPM,
			expectError:  true,
		},
		{
			name:         "EmptyNonce",
			extension:    hashNonce[:],
			pubKey:       pubKeyDER,
			nonce:        []byte{},
			platformType: attestation.SNPvTPM,
			expectError:  true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := certificateVerifier{}
			err := v.verifyCertificateExtension(c.extension, c.pubKey, c.nonce, c.platformType)
			if c.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Helper functions

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

func TestCAClient(t *testing.T) {
	t.Run("NewCAClient", func(t *testing.T) {
		agentToken := "test-token"
		client := NewCAClient(nil, agentToken)

		assert.NotNil(t, client)
		assert.Equal(t, agentToken, client.agentToken)
		assert.NotNil(t, client.client)
	})
}

func TestNewAttestedCAProvider(t *testing.T) {
	mockProvider := new(mocks.Provider)
	attestationProvider, err := NewAttestationProvider(mockProvider, attestation.SNPvTPM)
	require.NoError(t, err)

	subject := DefaultCertificateSubject()
	cvmID := "test-cvm-id"
	agentToken := "test-token"

	provider := NewAttestedCAProvider(attestationProvider, subject, nil, cvmID, agentToken)
	assert.NotNil(t, provider)
}

// TestCertificateWithAttestationExtension tests certificates with attestation extensions.
func TestCertificateWithAttestationExtension(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "policy")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	attestationPB := prepVerifyAttReport(t)
	err = setAttestationPolicy(attestationPB, tempDir)
	require.NoError(t, err)

	t.Run("CertificateWithValidAttestationExtension", func(t *testing.T) {
		// Create certificate with attestation extension
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		_, err = x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		require.NoError(t, err)

		nonce := make([]byte, 64)
		_, err = rand.Read(nonce)
		require.NoError(t, err)

		extension := pkix.Extension{
			Id:    SNPvTPMOID,
			Value: []byte("test-attestation-data"),
		}

		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				Organization: []string{"Test Org"},
			},
			NotBefore:       time.Now(),
			NotAfter:        time.Now().Add(24 * time.Hour),
			KeyUsage:        x509.KeyUsageDigitalSignature,
			ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			ExtraExtensions: []pkix.Extension{extension},
		}

		certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
		require.NoError(t, err)

		cert, err := x509.ParseCertificate(certDER)
		require.NoError(t, err)

		verifier := certificateVerifier{}
		err = verifier.verifyAttestationExtension(cert, nonce)

		// Expect error due to invalid attestation data, but extension should be found
		assert.Error(t, err)
		assert.NotContains(t, err.Error(), "attestation extension not found")
	})
}

// TestIntegrationScenarios tests end-to-end integration scenarios.
func TestIntegrationScenarios(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "policy")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	attestationPB := prepVerifyAttReport(t)
	err = setAttestationPolicy(attestationPB, tempDir)
	require.NoError(t, err)

	t.Run("FullSelfSignedFlow", func(t *testing.T) {
		// Setup mock provider
		mockProvider := new(mocks.Provider)
		mockProvider.On("Attestation", mock.Anything, mock.Anything).Return([]byte("mock-attestation"), nil)

		// Create provider
		provider, err := NewProvider(mockProvider, attestation.SNPvTPM, "", "", nil)
		require.NoError(t, err)

		// Generate certificate
		nonce := make([]byte, 64)
		_, err = rand.Read(nonce)
		require.NoError(t, err)

		serverName := hex.EncodeToString(nonce) + ".nonce"
		clientHello := &tls.ClientHelloInfo{ServerName: serverName}

		cert, err := provider.GetCertificate(clientHello)
		assert.NoError(t, err)
		assert.NotNil(t, cert)
		assert.NotEmpty(t, cert.Certificate)
		assert.NotNil(t, cert.PrivateKey)

		// Verify the generated certificate
		parsedCert, err := x509.ParseCertificate(cert.Certificate[0])
		require.NoError(t, err)

		// Check for attestation extension
		found := false
		for _, ext := range parsedCert.Extensions {
			if ext.Id.Equal(SNPvTPMOID) {
				found = true
				break
			}
		}
		assert.True(t, found, "Attestation extension should be present")
	})

	t.Run("FullCASignedFlow", func(t *testing.T) {
		mockSDK := sdkmocks.NewSDK(t)
		expectedCert := certssdk.Certificate{Certificate: testCertPEM}
		mockSDK.On("IssueFromCSRInternal", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(expectedCert, errors.SDKError(nil))

		mockProvider := new(mocks.Provider)
		mockProvider.On("Attestation", mock.Anything, mock.Anything).Return([]byte("mock-attestation"), nil)

		provider, err := NewProvider(mockProvider, attestation.SNPvTPM, "test-token", "test-cvm-id", mockSDK)
		require.NoError(t, err)

		nonce := make([]byte, 64)
		_, err = rand.Read(nonce)
		require.NoError(t, err)

		serverName := hex.EncodeToString(nonce) + ".nonce"
		clientHello := &tls.ClientHelloInfo{ServerName: serverName}

		cert, err := provider.GetCertificate(clientHello)
		require.NoError(t, err)
		require.NotNil(t, cert)
		require.NotEmpty(t, cert.Certificate)
		require.NotNil(t, cert.PrivateKey)

		parsedCert, err := x509.ParseCertificate(cert.Certificate[0])
		require.NoError(t, err)

		assert.NotNil(t, parsedCert.Subject)

		mockProvider.AssertExpectations(t)
		mockSDK.AssertExpectations(t)
	})
}

// TestConcurrentAccess tests concurrent access scenarios.
func TestConcurrentAccess(t *testing.T) {
	mockProvider := new(mocks.Provider)
	mockProvider.On("Attestation", mock.Anything, mock.Anything).Return([]byte("mock-attestation"), nil)

	provider, err := NewProvider(mockProvider, attestation.SNPvTPM, "", "", nil)
	require.NoError(t, err)

	const numGoroutines = 10
	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			nonce := make([]byte, 64)
			_, err := rand.Read(nonce)
			if err != nil {
				errors <- err
				return
			}

			serverName := hex.EncodeToString(nonce) + ".nonce"
			clientHello := &tls.ClientHelloInfo{ServerName: serverName}

			cert, err := provider.GetCertificate(clientHello)
			if err != nil {
				errors <- err
				return
			}

			if cert == nil {
				errors <- fmt.Errorf("nil certificate returned for goroutine %d", id)
				return
			}

			errors <- nil
		}(i)
	}

	// Collect results
	for i := 0; i < numGoroutines; i++ {
		err := <-errors
		assert.NoError(t, err)
	}
}

// TestEdgeCasesAndBoundaries tests edge cases and boundary conditions.
func TestEdgeCasesAndBoundaries(t *testing.T) {
	t.Run("LargeNonce", func(t *testing.T) {
		largeNonce := make([]byte, 1024) // Much larger than expected
		_, err := rand.Read(largeNonce)
		require.NoError(t, err)

		serverName := hex.EncodeToString(largeNonce) + ".nonce"
		_, err = extractNonceFromSNI(serverName)
		assert.Error(t, err) // Should fail due to invalid length
	})

	t.Run("MaxLengthServerName", func(t *testing.T) {
		// Create very long server name
		nonce := make([]byte, 64)
		_, err := rand.Read(nonce)
		require.NoError(t, err)

		longPrefix := strings.Repeat("a", 200)
		serverName := longPrefix + hex.EncodeToString(nonce) + ".nonce"

		_, err = extractNonceFromSNI(serverName)
		assert.Error(t, err) // Should fail due to invalid format
	})

	t.Run("MinimalValidNonce", func(t *testing.T) {
		nonce := make([]byte, 64) // Exactly the required length
		_, err := rand.Read(nonce)
		require.NoError(t, err)

		serverName := hex.EncodeToString(nonce) + ".nonce"
		extractedNonce, err := extractNonceFromSNI(serverName)

		assert.NoError(t, err)
		assert.Equal(t, nonce, extractedNonce)
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
			v := certificateVerifier{
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
			v := certificateVerifier{
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
		NotAfter:              time.Now().Add(24 * time.Hour),
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
