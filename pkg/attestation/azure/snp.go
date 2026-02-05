// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package azure

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/absmach/supermq/pkg/errors"
	"github.com/edgelesssys/go-azguestattestation/maa"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-sev-guest/tools/lib/report"
	"github.com/google/go-tpm-tools/proto/attest"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/vtpm"
	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
	"google.golang.org/protobuf/proto"
)

var (
	MaaURL             = "https://sharedeus2.eus2.attest.azure.net"
	ErrFetchAzureToken = errors.New("failed to fetch Azure token")
)

var (
	_ attestation.Provider = (*provider)(nil)
	_ attestation.Verifier = (*verifier)(nil)
)

type provider struct{}

func NewProvider() attestation.Provider {
	return provider{}
}

func (a provider) Attestation(teeNonce []byte, vTpmNonce []byte) ([]byte, error) {
	var tokenNonce [vtpm.Nonce]byte
	copy(tokenNonce[:], teeNonce)

	params, err := maa.NewParameters(context.Background(), tokenNonce[:], http.DefaultClient, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get report: %w", err)
	}

	snpReport, err := report.ParseAttestation(params.SNPReport, "bin")
	if err != nil {
		return nil, fmt.Errorf("failed to parse SNP report: %w", err)
	}

	quote, err := vtpm.FetchQuote(vTpmNonce)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch quote: %w", err)
	}

	quote.TeeAttestation = &attest.Attestation_SevSnpAttestation{
		SevSnpAttestation: snpReport,
	}
	return proto.Marshal(quote)
}

func (a provider) TeeAttestation(teeNonce []byte) ([]byte, error) {
	var tokenNonce [vtpm.Nonce]byte
	copy(tokenNonce[:], teeNonce)

	params, err := maa.NewParameters(context.Background(), tokenNonce[:], http.DefaultClient, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get report: %w", err)
	}

	return params.SNPReport, nil
}

func (a provider) VTpmAttestation(vTpmNonce []byte) ([]byte, error) {
	quote, err := vtpm.FetchQuote(vTpmNonce)
	if err != nil {
		return []byte{}, errors.Wrap(vtpm.ErrFetchQuote, err)
	}

	return proto.Marshal(quote)
}

func (a provider) AzureAttestationToken(tokenNonce []byte) ([]byte, error) {
	quote, err := FetchAzureAttestationToken(tokenNonce, MaaURL)
	if err != nil {
		return nil, errors.Wrap(ErrFetchAzureToken, err)
	}

	return quote, nil
}

type verifier struct {
	writer io.Writer
}

func NewVerifier(writer io.Writer) attestation.Verifier {
	return verifier{
		writer: writer,
	}
}

// VerifyEAT verifies an EAT token and extracts the binary report for verification.
func (v verifier) VerifyEAT(eatToken []byte, teeNonce []byte, vTpmNonce []byte) error {
	// EAT verification logic is handled by certificate_verifier calling VerifyWithCoRIM
	// But legacy interface might require VerifyEAT.
	// In certificate_verifier.go, platformVerifier returns attestation.Verifier.
	// certificate_verifier calls v.VerifyWithCoRIM directly (type assertion?).
	// No, attestation.Verifier interface must have VerifyWithCoRIM.
	// I previously updated Verifier interface to have VerifyWithCoRIM and VerifyEAT.
	// But VerifyEAT implementation here calls VerifyAttestation which calls legacy.
	// I should probably remove VerifyEAT from here if interface doesn't REQUIRE it or if I can stub it.
	// But certificate_verifier calls v.VerifyWithCoRIM.
	// Does it call VerifyEAT?
	// certificate_verifier call: `func (v *certificateVerifier) verifyCertificateExtension` calls `eat.DecodeCBOR` then `verifier.VerifyWithCoRIM`.
	// So VerifyEAT is NOT called by certificate_verifier.
	// Is VerifyEAT in interface?
	// If yes, I must keep it or stub it.
	// I'll stub it to return error "not implemented used VerifyWithCoRIM".
	return fmt.Errorf("VerifyEAT is deprecated, use VerifyWithCoRIM")
}

func (v verifier) VerifyWithCoRIM(report []byte, manifest *corim.UnsignedCorim) error {
	attestation := &attest.Attestation{}
	if err := proto.Unmarshal(report, attestation); err != nil {
		return fmt.Errorf("failed to unmarshal attestation report: %w", err)
	}

	// Extract measurement from SEV-SNP report if present
	snpRep := attestation.GetSevSnpAttestation()
	if snpRep == nil {
		return fmt.Errorf("no SEV-SNP attestation found in report")
	}

	measurement := snpRep.GetReport().GetMeasurement()
	if len(measurement) == 0 {
		return fmt.Errorf("no measurement in SEV-SNP report")
	}

	// Parse CoMID from CoRIM
	if len(manifest.Tags) == 0 {
		return fmt.Errorf("no tags in CoRIM")
	}

	for _, tag := range manifest.Tags {
		if !bytes.HasPrefix(tag, corim.ComidTag) {
			continue
		}

		tagValue := tag[len(corim.ComidTag):]

		var c comid.Comid
		if err := c.FromCBOR(tagValue); err != nil {
			return fmt.Errorf("failed to parse CoMID: %w", err)
		}

		// Match measurements
		if c.Triples.ReferenceValues != nil {
			for _, rv := range *c.Triples.ReferenceValues {
				if rv.Measurements.Valid() != nil {
					continue
				}
				for _, m := range rv.Measurements {
					if m.Val.Digests == nil {
						continue
					}
					for _, digest := range *m.Val.Digests {
						if string(digest.HashValue) == string(measurement) {
							return nil // Match found
						}
					}
				}
			}
		}
	}

	return fmt.Errorf("no matching reference value found in CoRIM for Azure SEV-SNP")
}

func FetchAzureAttestationToken(tokenNonce []byte, maaURL string) ([]byte, error) {
	token, err := maa.Attest(context.Background(), tokenNonce, maaURL, http.DefaultClient)
	if err != nil {
		return nil, fmt.Errorf("error fetching azure token: %w", err)
	}
	return []byte(token), nil
}

func validateToken(token string) (map[string]any, error) {
	unverifiedToken, _, err := new(jwt.Parser).ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	jku, jkuOk := unverifiedToken.Header["jku"].(string)
	if !jkuOk {
		return nil, fmt.Errorf("token is missing jku or kid in header")
	}

	MaaUrlCerts := MaaURL
	if MaaURL == "" {
		MaaUrlCerts = jku
	}

	keySet, err := maa.GetKeySet(context.Background(), MaaUrlCerts, http.DefaultClient)
	if err != nil {
		return nil, fmt.Errorf("failed to get key set: %w", err)
	}

	claims, err := maa.ValidateToken(token, keySet)
	if err != nil {
		return nil, fmt.Errorf("failed to validate token: %w", err)
	}

	return claims, nil
}
