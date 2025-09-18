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
	certssdk "github.com/absmach/certs/sdk"
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

// Platform-specific OIDs for certificate extensions
var (
	SNPvTPMOID = asn1.ObjectIdentifier{2, 99999, 1, 0}
	AzureOID   = asn1.ObjectIdentifier{2, 99999, 1, 1}
	TDXOID     = asn1.ObjectIdentifier{2, 99999, 1, 2}
)

// CertificateSubject contains certificate subject information
type CertificateSubject struct {
	Organization  string
	Country       string
	Province      string
	Locality      string
	StreetAddress string
	PostalCode    string
}

// DefaultCertificateSubject returns the default certificate subject for Ultraviolet
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

// CertificateProvider defines the interface for providing TLS certificates
type CertificateProvider interface {
	GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error)
}

// CertificateGenerator handles certificate creation
type CertificateGenerator interface {
	GenerateCertificate(privateKey *ecdsa.PrivateKey, subject CertificateSubject, extension pkix.Extension) ([]byte, error)
}

// UnifiedCertificateGenerator handles both self-signed and CA-signed certificates
type UnifiedCertificateGenerator struct {
	caURL         string
	cvmID         string
	ttl           time.Duration
	notAfterYears int
	useCA         bool
	caClient      *CAClient
}

// NewSelfSignedGenerator creates a generator for self-signed certificates
func NewSelfSignedGenerator() *UnifiedCertificateGenerator {
	return &UnifiedCertificateGenerator{
		notAfterYears: defaultNotAfterYears,
		useCA:         false,
	}
}

// NewCASignedGenerator creates a generator for CA-signed certificates
func NewCASignedGenerator(caURL, cvmID string) *UnifiedCertificateGenerator {
	return &UnifiedCertificateGenerator{
		caURL:    caURL,
		cvmID:    cvmID,
		ttl:      time.Hour * 24 * 365, // Default 1 year
		useCA:    true,
		caClient: NewCAClient(caURL),
	}
}

// SetTTL sets the certificate TTL for CA-signed certificates
func (g *UnifiedCertificateGenerator) SetTTL(ttl time.Duration) {
	g.ttl = ttl
}

func (g *UnifiedCertificateGenerator) GenerateCertificate(privateKey *ecdsa.PrivateKey, subject CertificateSubject, extension pkix.Extension) ([]byte, error) {
	if g.useCA {
		return g.caClient.RequestCertificate(privateKey, subject, extension, g.cvmID, g.ttl)
	}

	// Self-signed certificate generation
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			Organization:  []string{subject.Organization},
			Country:       []string{subject.Country},
			Province:      []string{subject.Province},
			Locality:      []string{subject.Locality},
			StreetAddress: []string{subject.StreetAddress},
			PostalCode:    []string{subject.PostalCode},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(g.notAfterYears, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{extension},
	}

	return x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &privateKey.PublicKey, privateKey)
}

// PlatformAttestationProvider handles platform attestation operations
type PlatformAttestationProvider struct {
	provider     attestation.Provider
	oid          asn1.ObjectIdentifier
	platformType attestation.PlatformType
}

// NewAttestationProvider creates a new attestation provider for the given platform type
func NewAttestationProvider(provider attestation.Provider, platformType attestation.PlatformType) (*PlatformAttestationProvider, error) {
	oid, err := getOID(platformType)
	if err != nil {
		return nil, fmt.Errorf("failed to get OID: %w", err)
	}

	return &PlatformAttestationProvider{
		provider:     provider,
		oid:          oid,
		platformType: platformType,
	}, nil
}

func (p *PlatformAttestationProvider) GetAttestation(pubKey []byte, nonce []byte) ([]byte, error) {
	teeNonce := append(pubKey, nonce...)
	hashNonce := sha3.Sum512(teeNonce)
	return p.provider.Attestation(hashNonce[:], hashNonce[:vtpm.Nonce])
}

func (p *PlatformAttestationProvider) GetOID() asn1.ObjectIdentifier {
	return p.oid
}

func (p *PlatformAttestationProvider) GetPlatformType() attestation.PlatformType {
	return p.platformType
}

// AttestedCertificateProvider provides attested TLS certificates
type AttestedCertificateProvider struct {
	attestationProvider *PlatformAttestationProvider
	certGenerator       CertificateGenerator
	subject             CertificateSubject
}

// NewAttestedProvider creates a new attested certificate provider
func NewAttestedProvider(
	attestationProvider *PlatformAttestationProvider,
	certGenerator CertificateGenerator,
	subject CertificateSubject,
) *AttestedCertificateProvider {
	return &AttestedCertificateProvider{
		attestationProvider: attestationProvider,
		certGenerator:       certGenerator,
		subject:             subject,
	}
}

func (p *AttestedCertificateProvider) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	pubKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	nonce, err := extractNonceFromSNI(clientHello.ServerName)
	if err != nil {
		return nil, fmt.Errorf("failed to extract nonce: %w", err)
	}

	attestationData, err := p.attestationProvider.GetAttestation(pubKeyDER, nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to get attestation: %w", err)
	}

	extension := pkix.Extension{
		Id:    p.attestationProvider.GetOID(),
		Value: attestationData,
	}

	certDERBytes, err := p.certGenerator.GenerateCertificate(privateKey, p.subject, extension)
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate: %w", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDERBytes},
		PrivateKey:  privateKey,
	}, nil
}

// Factory functions for creating complete certificate providers
func NewProvider(provider attestation.Provider, platformType attestation.PlatformType, caURL, cvmID string) (CertificateProvider, error) {
	attestationProvider, err := NewAttestationProvider(provider, platformType)
	if err != nil {
		return nil, fmt.Errorf("failed to create attestation provider: %w", err)
	}

	var certGenerator CertificateGenerator
	if caURL != "" && cvmID != "" {
		certGenerator = NewCASignedGenerator(caURL, cvmID)
	} else {
		certGenerator = NewSelfSignedGenerator()
	}

	subject := DefaultCertificateSubject()
	return NewAttestedProvider(attestationProvider, certGenerator, subject), nil
}

// CAClient handles communication with Certificate Authority
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

func (c *CAClient) RequestCertificate(privateKey *ecdsa.PrivateKey, subject CertificateSubject, extension pkix.Extension, cvmID string, ttl time.Duration) ([]byte, error) {
	csrMetadata := certs.CSRMetadata{
		Organization:    []string{subject.Organization},
		Country:         []string{subject.Country},
		Province:        []string{subject.Province},
		Locality:        []string{subject.Locality},
		StreetAddress:   []string{subject.StreetAddress},
		PostalCode:      []string{subject.PostalCode},
		ExtraExtensions: []pkix.Extension{extension},
	}

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

// CertificateVerifier handles certificate verification operations
type CertificateVerifier struct {
	rootCAs *x509.CertPool
}

func NewCertificateVerifier(rootCAs *x509.CertPool) *CertificateVerifier {
	return &CertificateVerifier{rootCAs: rootCAs}
}

func (v *CertificateVerifier) VerifyPeerCertificate(rawCerts [][]byte, _ [][]*x509.Certificate, nonce []byte) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("no certificates provided")
	}

	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("failed to parse x509 certificate: %w", err)
	}

	if err := v.verifyCertificateSignature(cert); err != nil {
		return fmt.Errorf("certificate signature verification failed: %w", err)
	}

	return v.verifyAttestationExtension(cert, nonce)
}

func (v *CertificateVerifier) verifyCertificateSignature(cert *x509.Certificate) error {
	rootCAs := v.rootCAs
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
		rootCAs.AddCert(cert)
	}

	opts := x509.VerifyOptions{
		Roots:       rootCAs,
		CurrentTime: time.Now(),
	}

	_, err := cert.Verify(opts)
	return err
}

func (v *CertificateVerifier) verifyAttestationExtension(cert *x509.Certificate, nonce []byte) error {
	for _, ext := range cert.Extensions {
		if platformType, err := getPlatformTypeFromOID(ext.Id); err == nil {
			pubKeyDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
			if err != nil {
				return fmt.Errorf("failed to marshal public key: %w", err)
			}
			return v.verifyCertificateExtension(ext.Value, pubKeyDER, nonce, platformType)
		}
	}
	return fmt.Errorf("attestation extension not found in certificate")
}

func (v *CertificateVerifier) verifyCertificateExtension(extension []byte, pubKey []byte, nonce []byte, platformType attestation.PlatformType) error {
	verifier, err := getPlatformVerifier(platformType)
	if err != nil {
		return fmt.Errorf("failed to get platform verifier: %w", err)
	}

	teeNonce := append(pubKey, nonce...)
	hashNonce := sha3.Sum512(teeNonce)

	if err = verifier.VerifyAttestation(extension, hashNonce[:], hashNonce[:vtpm.Nonce]); err != nil {
		return fmt.Errorf("failed to verify attestation: %w", err)
	}

	return nil
}

// Utility functions
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

func getOID(platformType attestation.PlatformType) (asn1.ObjectIdentifier, error) {
	switch platformType {
	case attestation.SNPvTPM:
		return SNPvTPMOID, nil
	case attestation.Azure:
		return AzureOID, nil
	case attestation.TDX:
		return TDXOID, nil
	default:
		return nil, fmt.Errorf("unsupported platform type: %d", platformType)
	}
}

func getPlatformTypeFromOID(oid asn1.ObjectIdentifier) (attestation.PlatformType, error) {
	switch {
	case oid.Equal(SNPvTPMOID):
		return attestation.SNPvTPM, nil
	case oid.Equal(AzureOID):
		return attestation.Azure, nil
	case oid.Equal(TDXOID):
		return attestation.TDX, nil
	default:
		return 0, fmt.Errorf("unsupported OID: %v", oid)
	}
}

func getPlatformVerifier(platformType attestation.PlatformType) (attestation.Verifier, error) {
	var verifier attestation.Verifier

	switch platformType {
	case attestation.SNPvTPM:
		verifier = vtpm.NewVerifier(nil)
	case attestation.Azure:
		verifier = azure.NewVerifier(nil)
	case attestation.TDX:
		verifier = tdx.NewVerifier()
	default:
		return nil, fmt.Errorf("unsupported platform type: %d", platformType)
	}

	err := verifier.JSONToPolicy(attestation.AttestationPolicyPath)
	if err != nil {
		return nil, err
	}
	return verifier, nil
}
