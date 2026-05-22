// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package azure

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	tdxabi "github.com/google/go-tdx-guest/abi"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
)

const (
	tdxAttestEndpoint = "attest/TdxVm"
	tdxAPIVersion     = "2025-06-01"
	tdxRuntimeBinary  = "Binary"
	tdxRuntimeJSON    = "JSON"

	azureHCLReportNVIndex     = 0x01400001
	azureHCLReportDataNVIndex = 0x01400002

	azureHCLSignature          = "HCLA"
	azureHCLVersion            = 2
	azureHCLRequestType        = 2
	azureHCLRuntimeDataVersion = 1
	azureHCLHashSHA256         = 1
	azureHCLReportTypeSNP      = 2
	azureHCLReportTypeTDX      = 4

	azureHCLHeaderSize          = 0x20
	azureHCLMaxHWReportSize     = 0x4a0
	azureHCLRuntimeDataOffset   = azureHCLHeaderSize + azureHCLMaxHWReportSize
	azureHCLRuntimeClaimsOffset = 0x14
	azureTDReportSize           = 0x400
	azureTDReportDataOffset     = 0x80
)

var (
	azureTDXHCLReportReader  = readAzureHCLReport
	azureTDXReportDataWriter = writeAzureTDXReportData
	azureTDXHCLRefreshDelay  = 3 * time.Second
	azureTDXIMDSQuoteURL     = "http://169.254.169.254/acc/tdquote"
)

// TDXQuoteFetcher fetches a raw TDX quote for the provided REPORT_DATA.
type TDXQuoteFetcher interface {
	FetchQuote(reportData [tdxabi.ReportDataSize]byte) ([]byte, error)
}

type TDXEvidenceFetcher interface {
	FetchEvidence(reportData [tdxabi.ReportDataSize]byte) (*azureTDXEvidence, error)
}

type defaultTDXQuoteFetcher struct{}

func (f defaultTDXQuoteFetcher) FetchQuote(reportData [tdxabi.ReportDataSize]byte) ([]byte, error) {
	evidence, err := f.FetchEvidence(reportData)
	if err != nil {
		return nil, err
	}

	return evidence.Quote, nil
}

func (f defaultTDXQuoteFetcher) FetchEvidence(reportData [tdxabi.ReportDataSize]byte) (*azureTDXEvidence, error) {
	hclReport, err := readFreshAzureTDXHCLReport(reportData)
	if err != nil {
		return nil, err
	}

	parsedReport, err := parseAzureHCLReport(hclReport)
	if err != nil {
		return nil, err
	}
	if parsedReport.reportType != azureHCLReportTypeTDX {
		return nil, fmt.Errorf("Azure HCL report is not TDX")
	}
	if err := validateAzureTDXRuntimeClaimsHash(parsedReport); err != nil {
		return nil, err
	}

	quote, err := DefaultAzureTDXIMDSClient.GetQuote(context.Background(), parsedReport.hwReport, http.DefaultClient)
	if err != nil {
		return nil, fmt.Errorf("failed to get Azure TDX quote from IMDS: %w", err)
	}

	return &azureTDXEvidence{
		Quote:       quote,
		RuntimeData: append([]byte(nil), parsedReport.runtimeClaims...),
	}, nil
}

// DefaultTDXQuoteFetcher is used by the Azure TDX provider and is replaceable in tests.
var DefaultTDXQuoteFetcher TDXQuoteFetcher = defaultTDXQuoteFetcher{}

// AzureTDXIMDSClient fetches an Azure TDX quote from the Azure Instance Metadata Service.
type AzureTDXIMDSClient interface {
	GetQuote(ctx context.Context, tdReport []byte, client *http.Client) ([]byte, error)
}

type defaultAzureTDXIMDSClient struct{}

// DefaultAzureTDXIMDSClient is used by the Azure TDX quote fetcher and is replaceable in tests.
var DefaultAzureTDXIMDSClient AzureTDXIMDSClient = &defaultAzureTDXIMDSClient{}

// AzureTDXClient submits Azure TDX VM attestation evidence to Microsoft Azure Attestation.
type AzureTDXClient interface {
	AttestTDXVM(ctx context.Context, quote []byte, runtimeData []byte, nonce []byte, maaURL string, client *http.Client) (string, error)
}

type defaultAzureTDXClient struct{}

// DefaultAzureTDXClient is used by Azure TDX token fetching and is replaceable in tests.
var DefaultAzureTDXClient AzureTDXClient = &defaultAzureTDXClient{}

type tdxAttestRequest struct {
	Quote       string       `json:"quote"`
	RuntimeData *tdxDataBlob `json:"runtimeData,omitempty"`
	Nonce       string       `json:"nonce,omitempty"`
}

type tdxDataBlob struct {
	Data     string `json:"data"`
	DataType string `json:"dataType"`
}

type tdxAttestResponse struct {
	Token string `json:"token"`
}

type tdxIMDSQuoteRequest struct {
	Report string `json:"report"`
}

type tdxIMDSQuoteResponse struct {
	Quote string `json:"quote"`
}

type azureTDXEvidence struct {
	Quote       []byte
	RuntimeData []byte
}

type azureHCLReport struct {
	reportType    uint32
	hashType      uint32
	hwReport      []byte
	runtimeClaims []byte
}

func isAzureTDX() bool {
	if azureTDXHCLReportReader == nil {
		return false
	}

	hclReport, err := azureTDXHCLReportReader()
	if err != nil {
		return false
	}

	parsedReport, err := parseAzureHCLReport(hclReport)
	return err == nil && parsedReport.reportType == azureHCLReportTypeTDX
}

func fetchAzureTDXQuote(teeNonce []byte) ([]byte, error) {
	if teeNonce == nil {
		return nil, fmt.Errorf("tee nonce is required for Azure TDX attestation")
	}
	if len(teeNonce) != tdxabi.ReportDataSize {
		return nil, fmt.Errorf("invalid tee nonce length: expected %d bytes, got %d bytes", tdxabi.ReportDataSize, len(teeNonce))
	}

	var reportData [tdxabi.ReportDataSize]byte
	copy(reportData[:], teeNonce)

	evidence, err := fetchAzureTDXEvidence(reportData, teeNonce)
	if err != nil {
		return nil, err
	}

	return evidence.Quote, nil
}

func (c *defaultAzureTDXClient) AttestTDXVM(ctx context.Context, quote []byte, runtimeData []byte, nonce []byte, maaURL string, client *http.Client) (string, error) {
	if maaURL == "" {
		return "", fmt.Errorf("maaURL is empty")
	}
	if client == nil {
		client = http.DefaultClient
	}

	maaURL, err := url.JoinPath(maaURL, tdxAttestEndpoint)
	if err != nil {
		return "", fmt.Errorf("parsing maaURL: %w", err)
	}
	maaURL += fmt.Sprintf("?api-version=%s", tdxAPIVersion)

	attestRequest := tdxAttestRequest{
		Quote: base64.RawURLEncoding.EncodeToString(quote),
	}
	if len(runtimeData) > 0 {
		attestRequest.RuntimeData = &tdxDataBlob{
			Data:     base64.RawURLEncoding.EncodeToString(runtimeData),
			DataType: tdxRuntimeDataType(runtimeData),
		}
	}
	if len(nonce) > 0 {
		attestRequest.Nonce = base64.RawURLEncoding.EncodeToString(nonce)
	}

	reqBytes, err := json.Marshal(attestRequest)
	if err != nil {
		return "", fmt.Errorf("marshaling TDX attestation request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, maaURL, bytes.NewReader(reqBytes))
	if err != nil {
		return "", fmt.Errorf("creating TDX attestation request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("doing TDX attestation request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if msg, err := io.ReadAll(resp.Body); err == nil && len(msg) > 0 {
			return "", fmt.Errorf("MAA returned %v: %s", resp.Status, msg)
		}
		return "", fmt.Errorf("MAA returned %v", resp.Status)
	}

	var attestResponse tdxAttestResponse
	if err := json.NewDecoder(resp.Body).Decode(&attestResponse); err != nil {
		return "", fmt.Errorf("decoding TDX attestation response: %w", err)
	}
	if attestResponse.Token == "" {
		return "", fmt.Errorf("azure TDX attestation token not found in response")
	}

	return attestResponse.Token, nil
}

func (c *defaultAzureTDXIMDSClient) GetQuote(ctx context.Context, tdReport []byte, client *http.Client) ([]byte, error) {
	if len(tdReport) != azureTDReportSize {
		return nil, fmt.Errorf("invalid TD report length: expected %d bytes, got %d bytes", azureTDReportSize, len(tdReport))
	}
	if client == nil {
		client = http.DefaultClient
	}

	quoteRequest := tdxIMDSQuoteRequest{
		Report: base64.RawURLEncoding.EncodeToString(tdReport),
	}

	reqBytes, err := json.Marshal(quoteRequest)
	if err != nil {
		return nil, fmt.Errorf("marshaling Azure TDX IMDS quote request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, azureTDXIMDSQuoteURL, bytes.NewReader(reqBytes))
	if err != nil {
		return nil, fmt.Errorf("creating Azure TDX IMDS quote request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("doing Azure TDX IMDS quote request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if msg, err := io.ReadAll(resp.Body); err == nil && len(msg) > 0 {
			return nil, fmt.Errorf("Azure TDX IMDS returned %v: %s", resp.Status, msg)
		}
		return nil, fmt.Errorf("Azure TDX IMDS returned %v", resp.Status)
	}

	var quoteResponse tdxIMDSQuoteResponse
	if err := json.NewDecoder(resp.Body).Decode(&quoteResponse); err != nil {
		return nil, fmt.Errorf("decoding Azure TDX IMDS quote response: %w", err)
	}
	if quoteResponse.Quote == "" {
		return nil, fmt.Errorf("Azure TDX IMDS quote not found in response")
	}

	quote, err := decodeBase64URL(quoteResponse.Quote)
	if err != nil {
		return nil, fmt.Errorf("decoding Azure TDX IMDS quote: %w", err)
	}

	return quote, nil
}

// FetchAzureTDXAttestationToken fetches an Azure Attestation token for an Azure TDX VM.
func FetchAzureTDXAttestationToken(tokenNonce []byte, maaURL string) ([]byte, error) {
	reportData := tdxReportDataFromRuntimeData(tokenNonce)
	evidence, err := fetchAzureTDXEvidence(reportData, tokenNonce)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Azure TDX quote: %w", err)
	}

	token, err := DefaultAzureTDXClient.AttestTDXVM(context.Background(), evidence.Quote, evidence.RuntimeData, tokenNonce, maaURL, http.DefaultClient)
	if err != nil {
		return nil, fmt.Errorf("error fetching azure TDX token: %w", err)
	}

	return []byte(token), nil
}

func tdxReportDataFromRuntimeData(runtimeData []byte) [tdxabi.ReportDataSize]byte {
	hash := sha256.Sum256(runtimeData)
	var reportData [tdxabi.ReportDataSize]byte
	copy(reportData[:sha256.Size], hash[:])
	return reportData
}

func fetchAzureTDXEvidence(reportData [tdxabi.ReportDataSize]byte, fallbackRuntimeData []byte) (*azureTDXEvidence, error) {
	if evidenceFetcher, ok := DefaultTDXQuoteFetcher.(TDXEvidenceFetcher); ok {
		return evidenceFetcher.FetchEvidence(reportData)
	}

	quote, err := DefaultTDXQuoteFetcher.FetchQuote(reportData)
	if err != nil {
		return nil, err
	}

	return &azureTDXEvidence{
		Quote:       quote,
		RuntimeData: append([]byte(nil), fallbackRuntimeData...),
	}, nil
}

func readFreshAzureTDXHCLReport(reportData [tdxabi.ReportDataSize]byte) ([]byte, error) {
	if azureTDXReportDataWriter != nil {
		if err := azureTDXReportDataWriter(reportData[:]); err != nil {
			return nil, fmt.Errorf("writing Azure TDX report data: %w", err)
		}
		if azureTDXHCLRefreshDelay > 0 {
			time.Sleep(azureTDXHCLRefreshDelay)
		}
	}
	if azureTDXHCLReportReader == nil {
		return nil, fmt.Errorf("Azure TDX HCL report reader is not configured")
	}

	hclReport, err := azureTDXHCLReportReader()
	if err != nil {
		return nil, fmt.Errorf("reading Azure TDX HCL report: %w", err)
	}

	return hclReport, nil
}

func readAzureHCLReport() ([]byte, error) {
	tpm, err := tpm2.OpenTPM()
	if err != nil {
		return nil, err
	}
	defer tpm.Close()

	return tpm2.NVReadEx(tpm, azureHCLReportNVIndex, tpm2.HandleOwner, "", 0)
}

func writeAzureTDXReportData(data []byte) error {
	if len(data) != tdxabi.ReportDataSize {
		return fmt.Errorf("invalid Azure TDX report data length: expected %d bytes, got %d bytes", tdxabi.ReportDataSize, len(data))
	}

	tpm, err := tpm2.OpenTPM()
	if err != nil {
		return err
	}
	defer tpm.Close()

	return writeAzureTDXReportDataToTPM(tpm, data)
}

func writeAzureTDXReportDataToTPM(tpm io.ReadWriter, data []byte) error {
	if len(data) > int(^uint16(0)) {
		return fmt.Errorf("Azure TDX report data is too large")
	}

	if err := ensureAzureTDXReportDataIndex(tpm, uint16(len(data))); err != nil {
		return err
	}
	if err := tpm2.NVWrite(tpm, tpm2.HandleOwner, azureHCLReportDataNVIndex, "", tpmutil.U16Bytes(data), 0); err != nil {
		return fmt.Errorf("writing Azure TDX report-data NV index: %w", err)
	}

	return nil
}

func ensureAzureTDXReportDataIndex(tpm io.ReadWriter, size uint16) error {
	pub, err := tpm2.NVReadPublic(tpm, azureHCLReportDataNVIndex)
	if err == nil {
		if pub.DataSize == size {
			return nil
		}
		if err := tpm2.NVUndefineSpace(tpm, "", tpm2.HandleOwner, azureHCLReportDataNVIndex); err != nil {
			return fmt.Errorf("undefining mismatched Azure TDX report-data NV index: %w", err)
		}
	}

	nvPub := tpm2.NVPublic{
		NVIndex:    azureHCLReportDataNVIndex,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.AttrOwnerWrite | tpm2.AttrOwnerRead,
		DataSize:   size,
	}
	authArea := tpm2.AuthCommand{
		Session:    tpm2.HandlePasswordSession,
		Attributes: tpm2.AttrContinueSession,
		Auth:       []byte(""),
	}
	if err := tpm2.NVDefineSpaceEx(tpm, tpm2.HandleOwner, "", nvPub, authArea); err != nil {
		return fmt.Errorf("defining Azure TDX report-data NV index: %w", err)
	}

	return nil
}

func parseAzureHCLReport(report []byte) (*azureHCLReport, error) {
	minSize := azureHCLRuntimeDataOffset + azureHCLRuntimeClaimsOffset
	if len(report) < minSize {
		return nil, fmt.Errorf("invalid Azure HCL report size: expected at least %d bytes, got %d bytes", minSize, len(report))
	}
	if string(report[:len(azureHCLSignature)]) != azureHCLSignature {
		return nil, fmt.Errorf("invalid Azure HCL report signature")
	}
	if version := binary.LittleEndian.Uint32(report[4:8]); version != azureHCLVersion {
		return nil, fmt.Errorf("invalid Azure HCL report version: expected %d, got %d", azureHCLVersion, version)
	}
	reportSize := binary.LittleEndian.Uint32(report[8:12])
	if reportSize > uint32(len(report)) {
		return nil, fmt.Errorf("invalid Azure HCL report size: header reports %d bytes, got %d bytes", reportSize, len(report))
	}
	if requestType := binary.LittleEndian.Uint32(report[12:16]); requestType != azureHCLRequestType {
		return nil, fmt.Errorf("invalid Azure HCL report request type: expected %d, got %d", azureHCLRequestType, requestType)
	}

	runtimeData := report[azureHCLRuntimeDataOffset:]
	dataSize := binary.LittleEndian.Uint32(runtimeData[0:4])
	if dataSize < azureHCLRuntimeClaimsOffset {
		return nil, fmt.Errorf("invalid Azure HCL runtime data size: %d", dataSize)
	}
	if azureHCLRuntimeDataOffset+int(dataSize) > len(report) {
		return nil, fmt.Errorf("invalid Azure HCL runtime data size: header reports %d bytes", dataSize)
	}
	if version := binary.LittleEndian.Uint32(runtimeData[4:8]); version != azureHCLRuntimeDataVersion {
		return nil, fmt.Errorf("invalid Azure HCL runtime data version: expected %d, got %d", azureHCLRuntimeDataVersion, version)
	}

	reportType := binary.LittleEndian.Uint32(runtimeData[8:12])
	if reportType != azureHCLReportTypeSNP && reportType != azureHCLReportTypeTDX {
		return nil, fmt.Errorf("invalid Azure HCL report type: %d", reportType)
	}

	hashType := binary.LittleEndian.Uint32(runtimeData[12:16])
	claimsSize := binary.LittleEndian.Uint32(runtimeData[16:20])
	claimsEnd := azureHCLRuntimeClaimsOffset + int(claimsSize)
	if claimsEnd > int(dataSize) {
		return nil, fmt.Errorf("invalid Azure HCL runtime claims size: %d", claimsSize)
	}

	hwReportSize := azureHCLMaxHWReportSize
	if reportType == azureHCLReportTypeTDX {
		hwReportSize = azureTDReportSize
	}
	if azureHCLHeaderSize+hwReportSize > len(report) {
		return nil, fmt.Errorf("invalid Azure HCL hardware report size: %d", hwReportSize)
	}

	return &azureHCLReport{
		reportType:    reportType,
		hashType:      hashType,
		hwReport:      append([]byte(nil), report[azureHCLHeaderSize:azureHCLHeaderSize+hwReportSize]...),
		runtimeClaims: append([]byte(nil), runtimeData[azureHCLRuntimeClaimsOffset:claimsEnd]...),
	}, nil
}

func validateAzureTDXRuntimeClaimsHash(report *azureHCLReport) error {
	if report.hashType != azureHCLHashSHA256 {
		return fmt.Errorf("unsupported Azure HCL runtime data hash type: %d", report.hashType)
	}
	if len(report.hwReport) < azureTDReportDataOffset+sha256.Size {
		return fmt.Errorf("invalid Azure TDX TD report size: %d", len(report.hwReport))
	}

	hash := sha256.Sum256(report.runtimeClaims)
	if !bytes.Equal(hash[:], report.hwReport[azureTDReportDataOffset:azureTDReportDataOffset+sha256.Size]) {
		return fmt.Errorf("Azure TDX runtime claims hash does not match TD report data")
	}

	return nil
}

func tdxRuntimeDataType(runtimeData []byte) string {
	if json.Valid(runtimeData) {
		return tdxRuntimeJSON
	}
	return tdxRuntimeBinary
}

func decodeBase64URL(value string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err == nil {
		return decoded, nil
	}

	return base64.URLEncoding.DecodeString(value)
}

func verifyTDXQuoteWithCoRIM(report []byte, manifest *corim.UnsignedCorim) error {
	decodedQuote, err := tdxabi.QuoteToProto(report)
	if err != nil {
		return fmt.Errorf("failed to parse TDX quote: %w", err)
	}

	quoteV4, ok := decodedQuote.(*tdxpb.QuoteV4)
	if !ok {
		return fmt.Errorf("unsupported TDX quote format")
	}

	tdReport := quoteV4.GetTdQuoteBody()
	if tdReport == nil {
		return fmt.Errorf("missing TDX quote body")
	}

	mrtd := tdReport.GetMrTd()
	if len(mrtd) == 0 {
		return fmt.Errorf("no MRTD in TDX quote")
	}

	if err := matchMeasurementInCoRIM(manifest, mrtd); err != nil {
		return fmt.Errorf("%w for Azure TDX", err)
	}

	return nil
}

func matchMeasurementInCoRIM(manifest *corim.UnsignedCorim, measurement []byte) error {
	if manifest == nil || len(manifest.Tags) == 0 {
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

		if c.Triples.ReferenceValues == nil {
			continue
		}
		for _, rv := range *c.Triples.ReferenceValues {
			for _, m := range rv.Measurements {
				if m.Val.Digests == nil {
					continue
				}
				for _, digest := range *m.Val.Digests {
					if bytes.Equal(digest.HashValue, measurement) {
						return nil
					}
				}
			}
		}
	}

	return fmt.Errorf("no matching reference value found in CoRIM")
}

// AzureTDXMeasurementData contains the fields extracted from an Azure TDX attestation token
// needed to construct a CoRIM policy for the TDX platform.
type AzureTDXMeasurementData struct {
	MRTD    string
	MRSEAM  string
	RTMRs   []string
	SEAMSVN uint64
}

// ExtractAzureTDXMeasurement extracts core TDX measurements from an Azure Attestation token.
func ExtractAzureTDXMeasurement(token string) (*AzureTDXMeasurementData, error) {
	claims, err := DefaultValidator.Validate(token)
	if err != nil {
		return nil, fmt.Errorf("failed to validate token: %w", err)
	}

	mrtd, ok := azureClaimString(claims, "tdx_mrtd")
	if !ok {
		return nil, fmt.Errorf("failed to get MRTD from claims")
	}

	mrSeam, _ := azureClaimString(claims, "tdx_mrseam")

	rtmrs := make([]string, 0, 4)
	for _, name := range []string{"tdx_rtmr0", "tdx_rtmr1", "tdx_rtmr2", "tdx_rtmr3"} {
		if value, ok := azureClaimString(claims, name); ok {
			rtmrs = append(rtmrs, value)
		}
	}

	seamSVN, _ := azureClaimUint64(claims, "tdx_seamsvn")

	return &AzureTDXMeasurementData{
		MRTD:    mrtd,
		MRSEAM:  mrSeam,
		RTMRs:   rtmrs,
		SEAMSVN: seamSVN,
	}, nil
}

func azureClaimString(claims map[string]any, name string) (string, bool) {
	if value, ok := claims[name].(string); ok {
		return value, true
	}

	tee, ok := claims["x-ms-isolation-tee"].(map[string]any)
	if !ok {
		return "", false
	}
	value, ok := tee[name].(string)
	return value, ok
}

func azureClaimUint64(claims map[string]any, name string) (uint64, bool) {
	value, ok := claims[name]
	if !ok {
		tee, teeOK := claims["x-ms-isolation-tee"].(map[string]any)
		if !teeOK {
			return 0, false
		}
		value, ok = tee[name]
		if !ok {
			return 0, false
		}
	}

	switch typed := value.(type) {
	case float64:
		return uint64(typed), true
	case int:
		return uint64(typed), true
	case uint64:
		return typed, true
	default:
		return 0, false
	}
}
