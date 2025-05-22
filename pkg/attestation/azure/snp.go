// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package azure

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"

	"github.com/absmach/magistrala/pkg/errors"
	"github.com/edgelesssys/go-azguestattestation/maa"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	"github.com/google/go-sev-guest/proto/check"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/tools/lib/report"
	"github.com/google/go-tpm-tools/proto/attest"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/quoteprovider"
	"github.com/ultravioletrs/cocos/pkg/attestation/vtpm"
	"google.golang.org/protobuf/proto"
)

var MaaURL = "https://sharedeus2.eus2.attest.azure.net"

var _ attestation.Provider = (*provider)(nil)

type provider struct {
	writer io.Writer
}

func New(writer io.Writer) attestation.Provider {
	return provider{writer: writer}
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

func (a provider) VerifTeeAttestation(report []byte, teeNonce []byte) error {
	attestationReport, err := abi.ReportCertsToProto(report)
	if err != nil {
		return errors.Wrap(fmt.Errorf("failed to convert TEE report to proto"), err)
	}

	return quoteprovider.VerifyAttestationReportTLS(attestationReport, teeNonce)
}

func (a provider) VerifVTpmAttestation(report []byte, vTpmNonce []byte) error {
	return vtpm.VerifyQuote(report, nil, vTpmNonce, a.writer)
}

func (a provider) VerifyAttestation(report []byte, teeNonce []byte, vTpmNonce []byte) error {
	var tokenNonce [vtpm.Nonce]byte
	copy(tokenNonce[:], teeNonce)

	quote := &attest.Attestation{}
	err := proto.Unmarshal(report, quote)
	if err != nil {
		return fmt.Errorf("failed to unmarshal vTPM quote: %w", err)
	}

	snpReport := quote.GetSevSnpAttestation()
	if err = quoteprovider.VerifyAttestationReportTLS(snpReport, nil); err != nil {
		return fmt.Errorf("failed to verify vTPM attestation report: %w", err)
	}

	return nil
}

func (a provider) AzureAttestationToken(tokenNonce []byte) ([]byte, error) {
	quote, err := vtpm.FetchAzureAttestation(tokenNonce, MaaURL)
	if err != nil {
		return nil, errors.Wrap(vtpm.ErrFetchAzureToken, err)
	}

	return quote, nil
}

func GenerateAttestationPolicy(token, product string, policy uint64) (*attestation.Config, error) {
	claims, err := validateToken(token)
	if err != nil {
		return nil, fmt.Errorf("failed to validate token: %w", err)
	}

	tee, ok := claims["x-ms-isolation-tee"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("failed to get tee from claims")
	}

	familyIdString, ok := tee["x-ms-sevsnpvm-familyId"].(string)
	if !ok {
		return nil, fmt.Errorf("failed to get familyId from claims")
	}

	familyId, err := hex.DecodeString(familyIdString)
	if err != nil {
		return nil, fmt.Errorf("failed to decode familyId: %w", err)
	}

	imageIdString, ok := tee["x-ms-sevsnpvm-imageId"].(string)
	if !ok {
		return nil, fmt.Errorf("failed to get imageId from claims")
	}
	imageId, err := hex.DecodeString(imageIdString)
	if err != nil {
		return nil, fmt.Errorf("failed to decode imageId: %w", err)
	}

	measurementString, ok := tee["x-ms-sevsnpvm-launchmeasurement"].(string)
	if !ok {
		return nil, fmt.Errorf("failed to get measurement from claims")
	}
	measurement, err := hex.DecodeString(measurementString)
	if err != nil {
		return nil, fmt.Errorf("failed to decode measurement: %w", err)
	}

	bootloaderVersion, ok := tee["x-ms-sevsnpvm-bootloader-svn"].(float64)
	if !ok {
		return nil, fmt.Errorf("failed to get bootloader version from claims")
	}

	teeVersion, ok := tee["x-ms-sevsnpvm-tee-svn"].(float64)
	if !ok {
		return nil, fmt.Errorf("failed to get tee version from claims")
	}

	snpVersion, ok := tee["x-ms-sevsnpvm-snpfw-svn"].(float64)
	if !ok {
		return nil, fmt.Errorf("failed to get snp version from claims")
	}

	microcodeVersion, ok := tee["x-ms-sevsnpvm-microcode-svn"].(float64)
	if !ok {
		return nil, fmt.Errorf("failed to get microcode version from claims")
	}

	minimalTCBParts := kds.TCBParts{
		BlSpl:    uint8(bootloaderVersion),
		TeeSpl:   uint8(teeVersion),
		SnpSpl:   uint8(snpVersion),
		UcodeSpl: uint8(microcodeVersion),
	}

	minimalTCB, err := kds.ComposeTCBParts(minimalTCBParts)
	if err != nil {
		return nil, fmt.Errorf("failed to compose TCB parts: %w", err)
	}

	guestSVN, ok := tee["x-ms-sevsnpvm-guestsvn"].(float64)
	if !ok {
		return nil, fmt.Errorf("failed to get guest SVN from claims")
	}

	idKeyDigestString, ok := tee["x-ms-sevsnpvm-idkeydigest"].(string)
	if !ok {
		return nil, fmt.Errorf("failed to get idKeyDigest from claims")
	}
	idKeyDigest, err := hex.DecodeString(idKeyDigestString)
	if err != nil {
		return nil, fmt.Errorf("failed to decode idKeyDigest: %w", err)
	}

	reportIDString, ok := tee["x-ms-sevsnpvm-reportid"].(string)
	if !ok {
		return nil, fmt.Errorf("failed to get reportID from claims")
	}
	reportID, err := hex.DecodeString(reportIDString)
	if err != nil {
		return nil, fmt.Errorf("failed to decode reportID: %w", err)
	}

	sevProduct := quoteprovider.GetProductName(product)

	return &attestation.Config{
		Config: &check.Config{
			RootOfTrust: &check.RootOfTrust{
				CheckCrl: true,
			},
			Policy: &check.Policy{
				ImageId:            imageId,
				FamilyId:           familyId,
				Measurement:        measurement,
				MinimumGuestSvn:    uint32(guestSVN),
				MinimumTcb:         uint64(minimalTCB),
				TrustedIdKeyHashes: [][]byte{idKeyDigest},
				ReportId:           reportID,
				Product:            &sevsnp.SevProduct{Name: sevProduct},
				Policy:             policy,
			},
		},
		PcrConfig: &attestation.PcrConfig{},
	}, nil
}

func validateToken(token string) (map[string]interface{}, error) {
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

func validateClaims(claims map[string]interface{}, nonce []byte) error {
	runtime, ok := claims["x-ms-runtime"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("failed to get runtime from claims")
	}

	payload, ok := runtime["client-payload"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("failed to get client payload from claims")
	}

	tokenNonce, ok := payload["nonce"].(string)
	if !ok {
		return fmt.Errorf("failed to get nonce from claims")
	}

	if tokenNonce != base64.StdEncoding.EncodeToString(nonce) {
		return fmt.Errorf("nonce mismatch: expected %s, got %s", base64.StdEncoding.EncodeToString(nonce), tokenNonce)
	}

	return nil
}
