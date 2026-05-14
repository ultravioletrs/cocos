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
	"net/http"
	"net/http/httptest"
	"testing"

	tdxabi "github.com/google/go-tdx-guest/abi"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	tdxtestdata "github.com/google/go-tdx-guest/testing/testdata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
	"github.com/veraison/swid"
)

type mockTDXQuoteFetcher struct {
	quote          []byte
	err            error
	gotReportData  [tdxabi.ReportDataSize]byte
	fetchQuoteCall bool
}

func (m *mockTDXQuoteFetcher) FetchQuote(reportData [tdxabi.ReportDataSize]byte) ([]byte, error) {
	m.fetchQuoteCall = true
	m.gotReportData = reportData
	if m.err != nil {
		return nil, m.err
	}
	return m.quote, nil
}

type mockTDXEvidenceFetcher struct {
	evidence         *azureTDXEvidence
	err              error
	gotReportData    [tdxabi.ReportDataSize]byte
	fetchEvidenceHit bool
}

func (m *mockTDXEvidenceFetcher) FetchQuote(reportData [tdxabi.ReportDataSize]byte) ([]byte, error) {
	evidence, err := m.FetchEvidence(reportData)
	if err != nil {
		return nil, err
	}
	return evidence.Quote, nil
}

func (m *mockTDXEvidenceFetcher) FetchEvidence(reportData [tdxabi.ReportDataSize]byte) (*azureTDXEvidence, error) {
	m.fetchEvidenceHit = true
	m.gotReportData = reportData
	if m.err != nil {
		return nil, m.err
	}
	return m.evidence, nil
}

type mockAzureTDXClient struct {
	token       string
	err         error
	gotQuote    []byte
	gotRuntime  []byte
	gotNonce    []byte
	gotMaaURL   string
	attestCalls int
}

func (m *mockAzureTDXClient) AttestTDXVM(_ context.Context, quote []byte, runtimeData []byte, nonce []byte, maaURL string, _ *http.Client) (string, error) {
	m.attestCalls++
	m.gotQuote = append([]byte(nil), quote...)
	m.gotRuntime = append([]byte(nil), runtimeData...)
	m.gotNonce = append([]byte(nil), nonce...)
	m.gotMaaURL = maaURL
	if m.err != nil {
		return "", m.err
	}
	return m.token, nil
}

type mockAzureTDXIMDSClient struct {
	quote        []byte
	err          error
	gotTDReport  []byte
	getQuoteCall bool
}

func (m *mockAzureTDXIMDSClient) GetQuote(_ context.Context, tdReport []byte, _ *http.Client) ([]byte, error) {
	m.getQuoteCall = true
	m.gotTDReport = append([]byte(nil), tdReport...)
	if m.err != nil {
		return nil, m.err
	}
	return m.quote, nil
}

func testAzureHCLReport(reportType uint32, runtimeClaims []byte) []byte {
	reportSize := azureHCLRuntimeDataOffset + azureHCLRuntimeClaimsOffset + len(runtimeClaims)
	hclReport := make([]byte, reportSize)
	copy(hclReport[:len(azureHCLSignature)], azureHCLSignature)
	binary.LittleEndian.PutUint32(hclReport[4:8], azureHCLVersion)
	binary.LittleEndian.PutUint32(hclReport[8:12], uint32(reportSize))
	binary.LittleEndian.PutUint32(hclReport[12:16], azureHCLRequestType)

	runtimeData := hclReport[azureHCLRuntimeDataOffset:]
	binary.LittleEndian.PutUint32(runtimeData[0:4], uint32(azureHCLRuntimeClaimsOffset+len(runtimeClaims)))
	binary.LittleEndian.PutUint32(runtimeData[4:8], azureHCLRuntimeDataVersion)
	binary.LittleEndian.PutUint32(runtimeData[8:12], reportType)
	binary.LittleEndian.PutUint32(runtimeData[12:16], azureHCLHashSHA256)
	binary.LittleEndian.PutUint32(runtimeData[16:20], uint32(len(runtimeClaims)))
	copy(runtimeData[azureHCLRuntimeClaimsOffset:], runtimeClaims)

	if reportType == azureHCLReportTypeTDX {
		hash := sha256.Sum256(runtimeClaims)
		copy(hclReport[azureHCLHeaderSize+azureTDReportDataOffset:], hash[:])
	}

	return hclReport
}

func TestProvider_TeeAttestation_AzureTDX(t *testing.T) {
	oldReader := azureTDXHCLReportReader
	oldFetcher := DefaultTDXQuoteFetcher
	defer func() {
		azureTDXHCLReportReader = oldReader
		DefaultTDXQuoteFetcher = oldFetcher
	}()

	azureTDXHCLReportReader = func() ([]byte, error) {
		return testAzureHCLReport(azureHCLReportTypeTDX, []byte(`{"keys":[]}`)), nil
	}
	fetcher := &mockTDXQuoteFetcher{quote: []byte("tdx-quote")}
	DefaultTDXQuoteFetcher = fetcher

	reportData := bytes.Repeat([]byte{0xAB}, tdxabi.ReportDataSize)
	got, err := NewProvider().TeeAttestation(reportData)

	require.NoError(t, err)
	assert.Equal(t, []byte("tdx-quote"), got)
	assert.True(t, fetcher.fetchQuoteCall)
	assert.Equal(t, reportData, fetcher.gotReportData[:])
}

func TestProvider_TeeAttestation_AzureTDX_InvalidNonce(t *testing.T) {
	oldReader := azureTDXHCLReportReader
	defer func() { azureTDXHCLReportReader = oldReader }()

	azureTDXHCLReportReader = func() ([]byte, error) {
		return testAzureHCLReport(azureHCLReportTypeTDX, []byte(`{"keys":[]}`)), nil
	}

	_, err := NewProvider().TeeAttestation([]byte("short"))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid tee nonce length")
}

func TestProvider_AzureAttestationToken_AzureTDX(t *testing.T) {
	oldReader := azureTDXHCLReportReader
	oldFetcher := DefaultTDXQuoteFetcher
	oldClient := DefaultAzureTDXClient
	oldMaaURL := MaaURL
	defer func() {
		azureTDXHCLReportReader = oldReader
		DefaultTDXQuoteFetcher = oldFetcher
		DefaultAzureTDXClient = oldClient
		MaaURL = oldMaaURL
	}()

	azureTDXHCLReportReader = func() ([]byte, error) {
		return testAzureHCLReport(azureHCLReportTypeTDX, []byte(`{"keys":[]}`)), nil
	}
	MaaURL = "https://tdx.example.attest.azure.net"

	fetcher := &mockTDXQuoteFetcher{quote: []byte("quote")}
	client := &mockAzureTDXClient{token: "tdx-token"}
	DefaultTDXQuoteFetcher = fetcher
	DefaultAzureTDXClient = client

	nonce := []byte("token-nonce")
	got, err := NewProvider().AzureAttestationToken(nonce)

	require.NoError(t, err)
	assert.Equal(t, []byte("tdx-token"), got)

	expectedReportData := tdxReportDataFromRuntimeData(nonce)
	assert.Equal(t, expectedReportData, fetcher.gotReportData)
	assert.Equal(t, []byte("quote"), client.gotQuote)
	assert.Equal(t, nonce, client.gotRuntime)
	assert.Equal(t, nonce, client.gotNonce)
	assert.Equal(t, MaaURL, client.gotMaaURL)
}

func TestFetchAzureTDXAttestationToken_UsesHCLRuntimeClaims(t *testing.T) {
	oldFetcher := DefaultTDXQuoteFetcher
	oldClient := DefaultAzureTDXClient
	defer func() {
		DefaultTDXQuoteFetcher = oldFetcher
		DefaultAzureTDXClient = oldClient
	}()

	runtimeClaims := []byte(`{"keys":[],"user-data":"nonce"}`)
	fetcher := &mockTDXEvidenceFetcher{
		evidence: &azureTDXEvidence{
			Quote:       []byte("quote"),
			RuntimeData: runtimeClaims,
		},
	}
	client := &mockAzureTDXClient{token: "tdx-token"}
	DefaultTDXQuoteFetcher = fetcher
	DefaultAzureTDXClient = client

	nonce := []byte("token-nonce")
	got, err := FetchAzureTDXAttestationToken(nonce, "https://tdx.example.attest.azure.net")

	require.NoError(t, err)
	assert.Equal(t, []byte("tdx-token"), got)
	assert.True(t, fetcher.fetchEvidenceHit)
	assert.Equal(t, tdxReportDataFromRuntimeData(nonce), fetcher.gotReportData)
	assert.Equal(t, runtimeClaims, client.gotRuntime)
	assert.Equal(t, nonce, client.gotNonce)
}

func TestFetchAzureTDXAttestationToken_FetchQuoteError(t *testing.T) {
	oldFetcher := DefaultTDXQuoteFetcher
	defer func() { DefaultTDXQuoteFetcher = oldFetcher }()

	DefaultTDXQuoteFetcher = &mockTDXQuoteFetcher{err: fmt.Errorf("quote unavailable")}

	_, err := FetchAzureTDXAttestationToken([]byte("nonce"), "https://tdx.example.attest.azure.net")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to fetch Azure TDX quote")
}

func TestDefaultTDXQuoteFetcher_FetchEvidence_AzureHCLIMDS(t *testing.T) {
	oldReader := azureTDXHCLReportReader
	oldWriter := azureTDXReportDataWriter
	oldDelay := azureTDXHCLRefreshDelay
	oldIMDSClient := DefaultAzureTDXIMDSClient
	defer func() {
		azureTDXHCLReportReader = oldReader
		azureTDXReportDataWriter = oldWriter
		azureTDXHCLRefreshDelay = oldDelay
		DefaultAzureTDXIMDSClient = oldIMDSClient
	}()

	runtimeClaims := []byte(`{"keys":[],"user-data":"fresh"}`)
	hclReport := testAzureHCLReport(azureHCLReportTypeTDX, runtimeClaims)
	var gotReportData []byte
	azureTDXReportDataWriter = func(data []byte) error {
		gotReportData = append([]byte(nil), data...)
		return nil
	}
	azureTDXHCLReportReader = func() ([]byte, error) {
		return hclReport, nil
	}
	azureTDXHCLRefreshDelay = 0
	imdsClient := &mockAzureTDXIMDSClient{quote: []byte("tdx-quote")}
	DefaultAzureTDXIMDSClient = imdsClient

	reportData := [tdxabi.ReportDataSize]byte{0xAB}
	evidence, err := defaultTDXQuoteFetcher{}.FetchEvidence(reportData)

	require.NoError(t, err)
	assert.Equal(t, reportData[:], gotReportData)
	assert.Equal(t, []byte("tdx-quote"), evidence.Quote)
	assert.Equal(t, runtimeClaims, evidence.RuntimeData)
	assert.True(t, imdsClient.getQuoteCall)
	assert.Len(t, imdsClient.gotTDReport, azureTDReportSize)
}

func TestDefaultAzureTDXClient_AttestTDXVM(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/attest/TdxVm", r.URL.Path)
		assert.Equal(t, tdxAPIVersion, r.URL.Query().Get("api-version"))
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		var req tdxAttestRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		assert.Equal(t, base64.RawURLEncoding.EncodeToString([]byte("quote")), req.Quote)
		require.NotNil(t, req.RuntimeData)
		assert.Equal(t, base64.RawURLEncoding.EncodeToString([]byte("runtime")), req.RuntimeData.Data)
		assert.Equal(t, tdxRuntimeBinary, req.RuntimeData.DataType)
		assert.Equal(t, base64.RawURLEncoding.EncodeToString([]byte("nonce")), req.Nonce)

		_, _ = w.Write([]byte(`{"token":"tdx-token"}`))
	}))
	defer server.Close()

	token, err := (&defaultAzureTDXClient{}).AttestTDXVM(
		context.Background(),
		[]byte("quote"),
		[]byte("runtime"),
		[]byte("nonce"),
		server.URL,
		server.Client(),
	)

	require.NoError(t, err)
	assert.Equal(t, "tdx-token", token)
}

func TestDefaultAzureTDXClient_AttestTDXVM_JSONRuntimeData(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req tdxAttestRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		require.NotNil(t, req.RuntimeData)
		assert.Equal(t, tdxRuntimeJSON, req.RuntimeData.DataType)

		_, _ = w.Write([]byte(`{"token":"tdx-token"}`))
	}))
	defer server.Close()

	_, err := (&defaultAzureTDXClient{}).AttestTDXVM(
		context.Background(),
		[]byte("quote"),
		[]byte(`{"keys":[]}`),
		[]byte("nonce"),
		server.URL,
		server.Client(),
	)

	require.NoError(t, err)
}

func TestDefaultAzureTDXClient_AttestTDXVM_ErrorStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad quote", http.StatusBadRequest)
	}))
	defer server.Close()

	_, err := (&defaultAzureTDXClient{}).AttestTDXVM(context.Background(), []byte("quote"), nil, nil, server.URL, server.Client())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "MAA returned 400 Bad Request")
}

func TestDefaultAzureTDXIMDSClient_GetQuote(t *testing.T) {
	oldURL := azureTDXIMDSQuoteURL
	defer func() { azureTDXIMDSQuoteURL = oldURL }()

	tdReport := bytes.Repeat([]byte{0xA5}, azureTDReportSize)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		var req tdxIMDSQuoteRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		assert.Equal(t, base64.RawURLEncoding.EncodeToString(tdReport), req.Report)

		resp := tdxIMDSQuoteResponse{
			Quote: base64.RawURLEncoding.EncodeToString([]byte("quote")),
		}
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	}))
	defer server.Close()
	azureTDXIMDSQuoteURL = server.URL

	quote, err := (&defaultAzureTDXIMDSClient{}).GetQuote(context.Background(), tdReport, server.Client())

	require.NoError(t, err)
	assert.Equal(t, []byte("quote"), quote)
}

func TestIsAzureTDX_UsesHCLReportType(t *testing.T) {
	oldReader := azureTDXHCLReportReader
	defer func() { azureTDXHCLReportReader = oldReader }()

	azureTDXHCLReportReader = func() ([]byte, error) {
		return testAzureHCLReport(azureHCLReportTypeSNP, []byte("runtime")), nil
	}
	assert.False(t, isAzureTDX())

	azureTDXHCLReportReader = func() ([]byte, error) {
		return testAzureHCLReport(azureHCLReportTypeTDX, []byte(`{"keys":[]}`)), nil
	}
	assert.True(t, isAzureTDX())

	azureTDXHCLReportReader = func() ([]byte, error) {
		return nil, fmt.Errorf("no vTPM")
	}
	assert.False(t, isAzureTDX())
}

func TestExtractAzureTDXMeasurement_Success(t *testing.T) {
	oldValidator := DefaultValidator
	defer func() { DefaultValidator = oldValidator }()

	DefaultValidator = &mockTokenValidator{
		validateFunc: func(token string) (map[string]any, error) {
			return map[string]any{
				"tdx_mrtd":     "mrtd",
				"tdx_mrseam":   "mrseam",
				"tdx_rtmr0":    "rtmr0",
				"tdx_rtmr1":    "rtmr1",
				"tdx_rtmr2":    "rtmr2",
				"tdx_rtmr3":    "rtmr3",
				"tdx_seamsvn":  float64(7),
				"unrelatedKey": "ignored",
			}, nil
		},
	}

	data, err := ExtractAzureTDXMeasurement("valid-token")

	require.NoError(t, err)
	assert.Equal(t, &AzureTDXMeasurementData{
		MRTD:    "mrtd",
		MRSEAM:  "mrseam",
		RTMRs:   []string{"rtmr0", "rtmr1", "rtmr2", "rtmr3"},
		SEAMSVN: 7,
	}, data)
}

func TestVerifier_VerifyWithCoRIM_AzureTDX(t *testing.T) {
	decodedQuote, err := tdxabi.QuoteToProto(tdxtestdata.RawQuote)
	require.NoError(t, err)

	quoteV4, ok := decodedQuote.(*tdxpb.QuoteV4)
	require.True(t, ok)
	mrtd := quoteV4.GetTdQuoteBody().GetMrTd()

	c := comid.NewComid()
	c.SetTagIdentity("tdx-tag", 0)

	m := comid.MustNewUintMeasurement(uint64(1))
	m.AddDigest(swid.Sha384, mrtd)
	m.SetRawValueBytes([]byte("raw"), nil)

	rv := comid.ReferenceValue{
		Environment: comid.Environment{
			Class: comid.NewClassOID("1.2.3.4"),
		},
		Measurements: comid.Measurements{*m},
	}
	c.AddReferenceValue(rv)

	manifest := corim.NewUnsignedCorim()
	manifest.SetID("test-tdx-corim")
	manifest.AddComid(*c)

	err = NewVerifier(&bytes.Buffer{}).VerifyWithCoRIM(tdxtestdata.RawQuote, manifest)
	assert.NoError(t, err)
}
