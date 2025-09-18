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
	vmpl2         = 2
	organization  = "Ultraviolet"
	country       = "Serbia"
	province      = ""
	locality      = "Belgrade"
	streetAddress = "Bulevar Arsenija Carnojevica 103"
	postalCode    = "11000"
	notAfterYear  = 1
	notAfterMonth = 0
	notAfterDay   = 0
)

var (
	SNPvTPMOID          = asn1.ObjectIdentifier{2, 99999, 1, 0}
	AzureOID            = asn1.ObjectIdentifier{2, 99999, 1, 1}
	TDXOID              = asn1.ObjectIdentifier{2, 99999, 1, 2}
	errCertificateParse = errors.New("failed to parse x509 certificate")
	errAttVerification  = errors.New("certificate is not self signed")
)

type csrReq struct {
	CSR string `json:"csr,omitempty"`
}

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

func verifyCertificateExtension(extension []byte, pubKey []byte, nonce []byte, pType attestation.PlatformType) error {
	teeNonce := append(pubKey, nonce...)
	hashNonce := sha3.Sum512(teeNonce)

	verifier, err := getPlatformVerifier(pType)
	if err != nil {
		return fmt.Errorf("failed to get platform verifier: %w", err)
	}

	if err = verifier.VerifyAttestation(extension, hashNonce[:], hashNonce[:vtpm.Nonce]); err != nil {
		fmt.Printf("failed to verify attestation: %v\n", err)
		return err
	}

	return nil
}

func GetCertificate(caUrl string, cvmId string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
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

		if caUrl == "" && cvmId == "" {
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

			csrData := string(csr.CSR)

			r := csrReq{
				CSR: csrData,
			}

			data, sdkErr := json.Marshal(r)
			if sdkErr != nil {
				return nil, fmt.Errorf("failed to marshal CSR request: %w", sdkErr)
			}

			notBefore := time.Now()
			notAfter := time.Now().AddDate(notAfterYear, notAfterMonth, notAfterDay)
			ttlString := notAfter.Sub(notBefore).String()

			query := url.Values{}
			query.Add("ttl", ttlString)
			query_string := query.Encode()

			certsEndpoint := "certs"
			csrEndpoint := "csrs"
			endpoint := fmt.Sprintf("%s/%s/%s", certsEndpoint, csrEndpoint, cvmId)

			url := fmt.Sprintf("%s/%s?%s", caUrl, endpoint, query_string)

			_, body, err := processRequest(http.MethodPost, url, data, nil, http.StatusOK)
			if err != nil {
				return nil, fmt.Errorf("failed to process request: %w", err)
			}

			var cert certssdk.Certificate
			if err := json.Unmarshal(body, &cert); err != nil {
				return nil, fmt.Errorf("failed to unmarshal certificate response: %w", err)
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

	// Sets a default value for the Content-Type.
	// Overridden if Content-Type is passed in the headers arguments.
	req.Header.Add("Content-Type", "application/json")

	for key, value := range headers {
		req.Header.Add(key, value)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return make(http.Header), []byte{}, errors.NewSDKError(err)
	}
	defer resp.Body.Close()
	sdkerr := errors.CheckError(resp, expectedRespCodes...)
	if sdkerr != nil {
		return make(http.Header), []byte{}, sdkerr
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return make(http.Header), []byte{}, errors.NewSDKError(err)
	}
	return resp.Header, body, nil
}

// VerifyPeerCertificateATLS verifies peer certificates for Attested TLS.
func VerifyPeerCertificateATLS(rawCerts [][]byte, _ [][]*x509.Certificate, nonce []byte, rootCAs *x509.CertPool) error {
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return errors.Wrap(errCertificateParse, err)
	}

	err = verifyCertificateSignature(cert, rootCAs)
	if err != nil {
		return errors.Wrap(errAttVerification, err)
	}

	for _, ext := range cert.Extensions {
		pType, err := getPlatformTypeFromOID(ext.Id)
		if err == nil {
			pubKeyDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
			if err != nil {
				return fmt.Errorf("failed to marshal public key to DER format: %w", err)
			}

			return verifyCertificateExtension(ext.Value, pubKeyDER, nonce, pType)
		}
	}

	return errors.New("attestation extension not found in certificate")
}

// VerifyCertificateSignature verifies the certificate signature against root CAs.
func verifyCertificateSignature(cert *x509.Certificate, rootCAs *x509.CertPool) error {
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
		rootCAs.AddCert(cert)
	}

	opts := x509.VerifyOptions{
		Roots:       rootCAs,
		CurrentTime: time.Now(),
	}

	if _, err := cert.Verify(opts); err != nil {
		return err
	}

	return nil
}
