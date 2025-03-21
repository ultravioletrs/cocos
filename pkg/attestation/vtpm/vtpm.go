// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package vtpm

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/absmach/magistrala/pkg/errors"
	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm-tools/server"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	config "github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/quoteprovider"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"
)

const (
	eventLog = "/sys/kernel/security/tpm0/binary_bios_measurements"
	Nonce    = 32
	PCR15    = 15
	Hash256  = 32
	Hash384  = 48
)

var (
	ExternalTPM   io.ReadWriteCloser
	ErrNoHashAlgo = errors.New("hash algo is not supported")
)

type VtpmAttest func(teeNonce []byte, vTPMNonce []byte, teeAttestaion bool) ([]byte, error)

type tpmWrapper struct {
	io.ReadWriteCloser
}

func (et tpmWrapper) EventLog() ([]byte, error) {
	return os.ReadFile(eventLog)
}

func OpenTpm() (io.ReadWriteCloser, error) {
	if ExternalTPM != nil {
		return tpmWrapper{ExternalTPM}, nil
	}

	tw := tpmWrapper{}
	var err error

	tw.ReadWriteCloser, err = tpm2.OpenTPM("/dev/tpmrm0")
	if os.IsNotExist(err) {
		tw.ReadWriteCloser, err = tpm2.OpenTPM("/dev/tpm0")
	}

	return tw, err
}

func ExtendPCR(pcrIndex int, value []byte) error {
	rwc, err := OpenTpm()
	if err != nil {
		return err
	}
	defer rwc.Close()

	fixedSha256Hash := sha3.Sum256(value)
	if err := tpm2.PCRExtend(rwc, tpmutil.Handle(pcrIndex), tpm2.AlgSHA256, fixedSha256Hash[:], ""); err != nil {
		return err
	}

	fixedSha384Hash := sha3.Sum384(value)
	if err := tpm2.PCRExtend(rwc, tpmutil.Handle(pcrIndex), tpm2.AlgSHA384, fixedSha384Hash[:], ""); err != nil {
		return err
	}

	return nil
}

func Attest(teeNonce []byte, vTPMNonce []byte, teeAttestaion bool) ([]byte, error) {
	attestation, err := fetchVTPMQuote(vTPMNonce)
	if err != nil {
		return []byte{}, err
	}

	if teeAttestaion {
		attestation, err = addTEEAttestation(attestation, teeNonce)
		if err != nil {
			return []byte{}, err
		}
	}

	return marshalQuote(attestation)
}

func FetchATLSQuote(pubKey, teeNonce, vTPMNonce []byte) ([]byte, error) {
	attestation, err := fetchVTPMQuote(vTPMNonce)
	if err != nil {
		return []byte{}, err
	}

	reportData, err := createTEEAttestationReportNonce(pubKey, attestation.GetAkPub(), teeNonce)
	if err != nil {
		return []byte{}, err
	}

	attestation, err = addTEEAttestation(attestation, reportData)
	if err != nil {
		return []byte{}, err
	}

	return marshalQuote(attestation)
}

func VTPMVerify(quote []byte, pubKeyTLS []byte, teeNonce []byte, vtpmNonce []byte) error {
	attestation := &attest.Attestation{}

	err := proto.Unmarshal(quote, attestation)
	if err != nil {
		return errors.Wrap(fmt.Errorf("failed to unmarshal quote"), err)
	}

	ak := attestation.GetAkPub()
	pub, err := tpm2.DecodePublic(ak)
	if err != nil {
		return err
	}

	cryptoPub, err := pub.Key()
	if err != nil {
		return err
	}

	reportData, err := createTEEAttestationReportNonce(pubKeyTLS, ak, teeNonce)
	if err != nil {
		return errors.Wrap(fmt.Errorf("failed to create TEE attestation report nonce"), err)
	}

	if err := quoteprovider.VerifyAttestationReportTLS(attestation.GetSevSnpAttestation(), reportData); err != nil {
		return fmt.Errorf("failed to verify TEE attestation report: %v", err)
	}

	_, err = server.VerifyAttestation(attestation, server.VerifyOpts{Nonce: vtpmNonce, TrustedAKs: []crypto.PublicKey{cryptoPub}})
	if err != nil {
		return errors.Wrap(fmt.Errorf("failed to verify attestation"), err)
	}

	s256, s384 := calculatePCRTLSKey(pubKeyTLS)

	if err := checkExpectedPCRValues(attestation, s256, s384); err != nil {
		return fmt.Errorf("PCR values do not match expected PCR values: %w", err)
	}

	return nil
}

// EmptyAttest is a dummy attestation function that returns an empty attestation report.
func EmptyAttest(teeNonce []byte, vTPMNonce []byte, teeAttestaion bool) ([]byte, error) {
	return []byte{}, nil
}

func publicKeyToBytes(pubKey interface{}) ([]byte, error) {
	derBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}
	return derBytes, nil
}

func createTEEAttestationReportNonce(pubKeyTLS []byte, ak []byte, nonce []byte) ([]byte, error) {
	pub, err := tpm2.DecodePublic(ak)
	if err != nil {
		return []byte{}, err
	}

	cryptoPub, err := pub.Key()
	if err != nil {
		return []byte{}, err
	}

	pubKeyBytes, err := publicKeyToBytes(cryptoPub)
	if err != nil {
		return []byte{}, err
	}

	reportData := append(append(pubKeyTLS, pubKeyBytes...), nonce...)
	hash := sha3.Sum512(reportData)

	return hash[:], nil
}

func marshalQuote(attestation *attest.Attestation) ([]byte, error) {
	out, err := proto.Marshal(attestation)
	if err != nil {
		return []byte{}, errors.Wrap(fmt.Errorf("failed to marshal vTPM attestation report"), err)
	}

	return out, nil
}

func fetchVTPMQuote(nonce []byte) (*attest.Attestation, error) {
	rwc, err := OpenTpm()
	if err != nil {
		return nil, err
	}
	defer rwc.Close()

	attestationKey, err := client.AttestationKeyRSA(rwc)
	if err != nil {
		return nil, errors.Wrap(fmt.Errorf("failed to create attestation key: %v", err), err)
	}
	defer attestationKey.Close()

	var fixedNonce [Nonce]byte
	copy(fixedNonce[:], nonce)
	attestOpts := client.AttestOpts{}
	attestOpts.Nonce = fixedNonce[:]

	attestOpts.TCGEventLog, err = client.GetEventLog(rwc)
	if err != nil {
		return nil, errors.Wrap(fmt.Errorf("failed to retrieve TCG Event Log: %v", err), err)
	}

	attestation, err := attestationKey.Attest(attestOpts)
	if err != nil {
		return nil, errors.Wrap(fmt.Errorf("failed to attest: %v", err), err)
	}

	return attestation, nil
}

func addTEEAttestation(attestation *attest.Attestation, nonce []byte) (*attest.Attestation, error) {
	rawTeeAttestation, err := quoteprovider.FetchAttestation(nonce)
	if err != nil {
		return attestation, fmt.Errorf("failed to fetch TEE attestation report: %v", err)
	}

	extReport, err := abi.ReportCertsToProto(rawTeeAttestation)
	if err != nil {
		return attestation, errors.Wrap(fmt.Errorf("failed to convert TEE report to proto"), err)
	}
	attestation.TeeAttestation = &attest.Attestation_SevSnpAttestation{
		SevSnpAttestation: extReport,
	}

	return attestation, nil
}

func checkExpectedPCRValues(attestation *attest.Attestation, ePcr256, ePcr384 []byte) error {
	quotes := attestation.GetQuotes()
	for i := range quotes {
		quote := quotes[i]
		var pcrMap map[string]string
		var pcr15 []byte
		switch quote.Pcrs.Hash {
		case tpm.HashAlgo_SHA256:
			pcrMap = config.AttestationPolicy.PcrConfig.PCRValues.Sha256
			pcr15 = ePcr256
		case tpm.HashAlgo_SHA384:
			pcrMap = config.AttestationPolicy.PcrConfig.PCRValues.Sha384
			pcr15 = ePcr384
		case tpm.HashAlgo_SHA1:
			pcrMap = config.AttestationPolicy.PcrConfig.PCRValues.Sha1
			pcr15 = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
		default:
			return errors.Wrap(ErrNoHashAlgo, fmt.Errorf("algo: %s", tpm.HashAlgo_name[int32(quote.Pcrs.Hash)]))
		}

		pcr15Index := uint32(15)
		if !bytes.Equal(quote.Pcrs.Pcrs[pcr15Index], pcr15) {
			return fmt.Errorf("for algo %s PCR[15] expected %s but found %s", tpm.HashAlgo_name[int32(quote.Pcrs.Hash)], hex.EncodeToString(pcr15), hex.EncodeToString(quote.Pcrs.Pcrs[pcr15Index]))
		}

		for i, v := range pcrMap {
			index, err := strconv.ParseInt(i, 10, 32)
			if err != nil {
				return errors.Wrap(fmt.Errorf("error converting PCR index to int32"), err)
			}
			value, err := hex.DecodeString(v)
			if err != nil {
				return errors.Wrap(fmt.Errorf("error converting PCR value to byte"), err)
			}
			if !bytes.Equal(quote.Pcrs.Pcrs[uint32(index)], value) {
				return fmt.Errorf("for algo %s PCR[%d] expected %s but found %s", tpm.HashAlgo_name[int32(quote.Pcrs.Hash)], index, hex.EncodeToString(value), hex.EncodeToString(quote.Pcrs.Pcrs[uint32(index)]))
			}
		}
	}
	return nil
}

// Return SHA256 and SHA384 values of the input public key.
func calculatePCRTLSKey(pubKey []byte) ([]byte, []byte) {
	init256 := make([]byte, Hash256)
	init384 := make([]byte, Hash384)

	key256 := sha3.Sum256(pubKey)
	key384 := sha3.Sum384(pubKey)

	pcrValue256 := append(init256, key256[:]...)
	pcrValue384 := append(init384, key384[:]...)

	newPcr256 := sha256.Sum256(pcrValue256)
	newPcr384 := sha512.Sum384(pcrValue384)

	return newPcr256[:], newPcr384[:]
}
