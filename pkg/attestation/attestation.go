package attest

import (
	"fmt"
	"io"
	"os"
	"path"
	"time"

	"github.com/absmach/magistrala/pkg/errors"
	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/proto/check"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/validate"
	"github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"
	"github.com/google/logger"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/agent/quoteprovider"
)

const (
	cocosDirectory        = ".cocos"
	caBundleName          = "ask_ark.pem"
	attestationReportSize = 0x4A0
)

var (
	AttConfigurationSEVSNP = AttestationConfiguration{}
	timeout                = time.Minute * 2
	maxTryDelay            = time.Second * 30
)

var (
	errAttVerification = errors.New("attestation verification failed")
	errAttValidation   = errors.New("attestation validation failed")
)

type AttestationConfiguration struct {
	SNPPolicy   *check.Policy      `json:"snp_policy,omitempty"`
	RootOfTrust *check.RootOfTrust `json:"root_of_trust,omitempty"`
}

func VerifyAttestationReportTLS(attestationBytes []byte, reportData []byte) int {
	logger.Init("", false, false, io.Discard)

	AttConfigurationSEVSNP.SNPPolicy.ReportData = reportData[:]

	// Attestation verification and validation
	sopts, err := verify.RootOfTrustToOptions(AttConfigurationSEVSNP.RootOfTrust)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", errors.Wrap(errAttVerification, err))
		return -1
	}

	sopts.Product = AttConfigurationSEVSNP.SNPPolicy.Product
	sopts.Getter = &trust.RetryHTTPSGetter{
		Timeout:       timeout,
		MaxRetryDelay: maxTryDelay,
		Getter:        &trust.SimpleHTTPSGetter{},
	}

	attestationPB, err := abi.ReportCertsToProto(attestationBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", errors.Wrap(errAttVerification, err))
		return -1
	}

	if err := fillInAttestationLocal(attestationPB); err != nil {
		fmt.Fprintf(os.Stderr, "%v", err)
		return -1
	}

	if err = verify.SnpAttestation(attestationPB, sopts); err != nil {
		fmt.Fprintf(os.Stderr, "%v", errors.Wrap(errAttVerification, err))
		return -1
	}

	opts, err := validate.PolicyToOptions(AttConfigurationSEVSNP.SNPPolicy)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", errors.Wrap(errAttVerification, err))
		return -1
	}

	if err = validate.SnpAttestation(attestationPB, opts); err != nil {
		fmt.Fprintf(os.Stderr, "%v", errors.Wrap(errAttValidation, err))
		return -1
	}

	return 0
}

func fillInAttestationLocal(attestation *sevsnp.Attestation) error {
	product := AttConfigurationSEVSNP.RootOfTrust.ProductLine

	chain := attestation.GetCertificateChain()
	if chain == nil {
		chain = &sevsnp.CertificateChain{}
		attestation.CertificateChain = chain
	}
	if len(chain.GetAskCert()) == 0 || len(chain.GetArkCert()) == 0 {
		homePath, err := os.UserHomeDir()
		if err != nil {
			return err
		}

		bundleFilePath := path.Join(homePath, cocosDirectory, product, caBundleName)
		if _, err := os.Stat(bundleFilePath); err == nil {
			amdRootCerts := trust.AMDRootCerts{}
			if err := amdRootCerts.FromKDSCert(bundleFilePath); err != nil {
				return err
			}

			chain.ArkCert = amdRootCerts.ProductCerts.Ark.Raw
			chain.AskCert = amdRootCerts.ProductCerts.Ask.Raw
		}
	}

	return nil
}

func FetchAttestation(reportDataSlice []byte) []byte {
	var reportData [agent.ReportDataSize]byte

	qp, err := quoteprovider.GetQuoteProvider()
	if err != nil {
		return []byte{}
	}

	if len(reportData) > agent.ReportDataSize {
		return []byte{}
	}
	copy(reportData[:], reportDataSlice)

	rawQuote, err := qp.GetRawQuote(reportData)
	if err != nil {
		return []byte{}
	}

	return rawQuote
}
