// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package azure

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"

	"github.com/edgelesssys/go-azguestattestation/maa"
	"github.com/goccy/go-json"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	"github.com/google/go-sev-guest/proto/check"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/tools/lib/report"
	"github.com/google/go-tpm-tools/proto/attest"
	attestations "github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/quoteprovider"
	"github.com/ultravioletrs/cocos/pkg/attestation/vtpm"
	"google.golang.org/protobuf/proto"
)

var MaaURL = "https://sharedeus2.eus2.attest.azure.net"

var _ attestations.Provider = (*provider)(nil)

type AttestationData struct {
	TpmQuote    []byte `json:"quote"`
	Token       []byte `json:"data"`
	RuntimeData []byte `json:"runtime_data"`
}

type provider struct {
	ToeknNonce []byte
	VTpmNonce  []byte
}

func New(teeNonce, vtpmNonce []byte) attestations.Provider {
	var fixedNonce [vtpm.Nonce]byte
	copy(fixedNonce[:], teeNonce)

	return &provider{
		ToeknNonce: fixedNonce[:],
		VTpmNonce:  vtpmNonce,
	}
}

func (a provider) FetchAttestation() ([]byte, error) {
	token, err := maa.Attest(context.Background(), a.ToeknNonce, MaaURL, http.DefaultClient)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Azure attestation token: %w", err)
	}

	params, err := maa.NewParameters(context.Background(), a.ToeknNonce, http.DefaultClient, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get report: %w", err)
	}

	snpReport, err := report.ParseAttestation(params.SNPReport, "bin")
	if err != nil {
		return nil, fmt.Errorf("failed to parse SNP report: %w", err)
	}

	quote, err := vtpm.FetchQuote(a.VTpmNonce)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch quote: %w", err)
	}

	quote.TeeAttestation = &attest.Attestation_SevSnpAttestation{
		SevSnpAttestation: snpReport,
	}

	quoteByte, err := proto.Marshal(quote)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal quote: %w", err)
	}

	attestationData := &AttestationData{
		TpmQuote:    quoteByte,
		Token:       []byte(token),
		RuntimeData: params.RuntimeData,
	}

	attestDataByte, err := json.Marshal(attestationData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal attestation data: %w", err)
	}

	return attestDataByte, nil
}

func (a provider) VerifyAttestation(report []byte) error {
	var attestationData AttestationData
	err := json.Unmarshal(report, &attestationData)
	if err != nil {
		return fmt.Errorf("failed to unmarshal attestation data: %w", err)
	}

	token := string(attestationData.Token)

	claims, err := validateToken(token)
	if err != nil {
		return fmt.Errorf("failed to validate token: %w", err)
	}

	if err = validateClaims(claims, a.ToeknNonce); err != nil {
		return fmt.Errorf("failed to validate claims: %w", err)
	}

	quote := &attest.Attestation{}
	err = proto.Unmarshal(attestationData.TpmQuote, quote)
	if err != nil {
		return fmt.Errorf("failed to unmarshal vTPM quote: %w", err)
	}

	runtimeData := attestationData.RuntimeData
	rData := sha256.Sum256(runtimeData)
	reportData := make([]byte, abi.ReportDataSize)
	copy(reportData, rData[:])

	snpReport := quote.GetSevSnpAttestation()

	if err = quoteprovider.VerifyAttestationReportTLS(snpReport, reportData); err != nil {
		return fmt.Errorf("failed to verify vTPM attestation report: %w", err)
	}

	return nil
}

func GenerateAttestationPolicy(token string, product string, policy uint64) (*attestations.Config, error) {
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

	return &attestations.Config{
		Config: &check.Config{
			RootOfTrust: &check.RootOfTrust{
				CheckCrl: true,
			},
			Policy: &check.Policy{
				ImageId:         imageId,
				FamilyId:        familyId,
				Measurement:     measurement,
				MinimumGuestSvn: uint32(guestSVN),
				MinimumTcb:      uint64(minimalTCB),
				TrustedIdKeys:   [][]byte{idKeyDigest},
				ReportId:        reportID,
				Product:         &sevsnp.SevProduct{Name: sevProduct},
				Policy:          policy,
			},
		},
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
