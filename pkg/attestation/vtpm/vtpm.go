// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package vtpm

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/absmach/magistrala/pkg/errors"
	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/proto/attest"
	ptpm "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm-tools/server"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	attestations "github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/quoteprovider"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
)

var _ attestations.Provider = (*provider)(nil)

const (
	eventLog = "/sys/kernel/security/tpm0/binary_bios_measurements"
	Nonce    = 32
	PCR15    = 15
	Hash1    = 20
	Hash256  = 32
	Hash384  = 48
)

var (
	ExternalTPM   io.ReadWriteCloser
	ErrNoHashAlgo = errors.New("hash algo is not supported")
	ErrFetchQuote = errors.New("failed to fetch vTPM quote")
)

type tpm struct {
	io.ReadWriteCloser
}

func (et tpm) EventLog() ([]byte, error) {
	return os.ReadFile(eventLog)
}

func OpenTpm() (io.ReadWriteCloser, error) {
	if ExternalTPM != nil {
		return tpm{ExternalTPM}, nil
	}

	tw := tpm{}
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

type provider struct {
	pubKey        []byte
	teeAttestaion bool
	vmpl          uint
	writer        io.Writer
}

func New(pubKey []byte, teeAttestation bool, vmpl uint, writer io.Writer) attestations.Provider {
	return &provider{
		pubKey:        pubKey,
		teeAttestaion: teeAttestation,
		vmpl:          vmpl,
		writer:        writer,
	}
}

func (v provider) Attestation(teeNonce []byte, vTpmNonce []byte) ([]byte, error) {
	return Attest(teeNonce, vTpmNonce, v.teeAttestaion, v.vmpl)
}

func (v provider) TeeAttestation(teeNonce []byte) ([]byte, error) {
	return quoteprovider.FetchAttestation(teeNonce, v.vmpl)
}

func (v provider) VTpmAttestation(vTpmNonce []byte) ([]byte, error) {
	quote, err := FetchQuote(vTpmNonce)
	if err != nil {
		return []byte{}, errors.Wrap(ErrFetchQuote, err)
	}

	return proto.Marshal(quote)
}

func (v provider) VerifTeeAttestation(report []byte, teeNonce []byte) error {
	attestReport, err := abi.ReportToProto(report)
	if err != nil {
		return errors.Wrap(fmt.Errorf("failed to convert TEE report to proto"), err)
	}

	attestationReport := sevsnp.Attestation{Report: attestReport, CertificateChain: nil}
	return quoteprovider.VerifyAttestationReportTLS(&attestationReport, teeNonce)
}

func (v provider) VerifVTpmAttestation(report []byte, vTpmNonce []byte) error {
	return VerifyQuote(report, v.pubKey, vTpmNonce, v.writer)
}

func (v provider) VerifyAttestation(report []byte, teeNonce []byte, vTpmNonce []byte) error {
	return VTPMVerify(report, v.pubKey, teeNonce, vTpmNonce, v.writer)
}

func Attest(teeNonce []byte, vTPMNonce []byte, teeAttestaion bool, vmpl uint) ([]byte, error) {
	attestation, err := FetchQuote(vTPMNonce)
	if err != nil {
		return []byte{}, err
	}

	if teeAttestaion {
		err = addTEEAttestation(attestation, teeNonce, vmpl)
		if err != nil {
			return []byte{}, err
		}
	}

	return marshalQuote(attestation)
}

func VTPMVerify(quote []byte, pubKeyTLS []byte, teeNonce []byte, vtpmNonce []byte, writer io.Writer) error {
	if err := VerifyQuote(quote, pubKeyTLS, vtpmNonce, writer); err != nil {
		return fmt.Errorf("failed to verify vTPM quote: %v", err)
	}

	attestation := &attest.Attestation{}

	err := proto.Unmarshal(quote, attestation)
	if err != nil {
		return errors.Wrap(fmt.Errorf("failed to unmarshal quote"), err)
	}

	if err := quoteprovider.VerifyAttestationReportTLS(attestation.GetSevSnpAttestation(), teeNonce); err != nil {
		return fmt.Errorf("failed to verify TEE attestation report: %v", err)
	}

	return nil
}

func VerifyQuote(quote []byte, pubKeyTLS []byte, vtpmNonce []byte, writer io.Writer) error {
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

	ms, err := server.VerifyAttestation(attestation, server.VerifyOpts{Nonce: vtpmNonce, TrustedAKs: []crypto.PublicKey{cryptoPub}})
	if err != nil {
		return errors.Wrap(fmt.Errorf("failed to verify attestation"), err)
	}

	s256, s384 := calculatePCRTLSKey(pubKeyTLS)

	if err := checkExpectedPCRValues(attestation, s256, s384); err != nil {
		return fmt.Errorf("PCR values do not match expected PCR values: %w", err)
	}

	if writer != nil {
		marshalOptions := prototext.MarshalOptions{Multiline: true, EmitASCII: true}

		out, err := marshalOptions.Marshal(ms)
		if err != nil {
			return nil
		}

		if _, err := writer.Write(out); err != nil {
			return fmt.Errorf("failed to write verified attestation report: %v", err)
		}
	}

	return nil
}

func marshalQuote(attestation *attest.Attestation) ([]byte, error) {
	out, err := proto.Marshal(attestation)
	if err != nil {
		return []byte{}, errors.Wrap(fmt.Errorf("failed to marshal vTPM attestation report"), err)
	}

	return out, nil
}

func FetchQuote(nonce []byte) (*attest.Attestation, error) {
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

func addTEEAttestation(attestation *attest.Attestation, nonce []byte, vmpl uint) error {
	rawTeeAttestation, err := quoteprovider.FetchAttestation(nonce, vmpl)
	if err != nil {
		return fmt.Errorf("failed to fetch TEE attestation report: %v", err)
	}

	extReport, err := abi.ReportCertsToProto(rawTeeAttestation)
	if err != nil {
		return errors.Wrap(fmt.Errorf("failed to convert TEE report to proto"), err)
	}
	attestation.TeeAttestation = &attest.Attestation_SevSnpAttestation{
		SevSnpAttestation: extReport,
	}

	return nil
}

func checkExpectedPCRValues(attestation *attest.Attestation, ePcr256, ePcr384 []byte) error {
	quotes := attestation.GetQuotes()
	for i := range quotes {
		quote := quotes[i]
		var pcrMap map[string]string
		var pcr15 []byte
		switch quote.Pcrs.Hash {
		case ptpm.HashAlgo_SHA256:
			pcrMap = attestations.AttestationPolicy.PcrConfig.PCRValues.Sha256
			if ePcr256 == nil {
				pcr15 = make([]byte, 32)
			} else {
				pcr15 = ePcr256
			}
		case ptpm.HashAlgo_SHA384:
			pcrMap = attestations.AttestationPolicy.PcrConfig.PCRValues.Sha384
			if ePcr384 == nil {
				pcr15 = make([]byte, 48)
			} else {
				pcr15 = ePcr384
			}
		case ptpm.HashAlgo_SHA1:
			pcrMap = attestations.AttestationPolicy.PcrConfig.PCRValues.Sha1
			pcr15 = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
		default:
			return errors.Wrap(ErrNoHashAlgo, fmt.Errorf("algo: %s", ptpm.HashAlgo_name[int32(quote.Pcrs.Hash)]))
		}

		pcr15Index := uint32(15)
		if !bytes.Equal(quote.Pcrs.Pcrs[pcr15Index], pcr15) {
			return fmt.Errorf("for algo %s PCR[15] expected %s but found %s", ptpm.HashAlgo_name[int32(quote.Pcrs.Hash)], hex.EncodeToString(pcr15), hex.EncodeToString(quote.Pcrs.Pcrs[pcr15Index]))
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
				return fmt.Errorf("for algo %s PCR[%d] expected %s but found %s", ptpm.HashAlgo_name[int32(quote.Pcrs.Hash)], index, hex.EncodeToString(value), hex.EncodeToString(quote.Pcrs.Pcrs[uint32(index)]))
			}
		}
	}
	return nil
}

// Return SHA256 and SHA384 values of the input public key.
func calculatePCRTLSKey(pubKey []byte) ([]byte, []byte) {
	if len(pubKey) == 0 {
		return nil, nil
	}

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

func getPCRValue(index int, algorithm tpm2.Algorithm) ([]byte, error) {
	rwc, err := OpenTpm()
	if err != nil {
		return nil, err
	}
	defer rwc.Close()

	pcrValue, err := tpm2.ReadPCR(rwc, index, algorithm)
	if err != nil {
		return nil, err
	}

	return pcrValue, nil
}

func GetPCRSHA1Value(index int) ([]byte, error) {
	return getPCRValue(index, tpm2.AlgSHA1)
}

func GetPCRSHA256Value(index int) ([]byte, error) {
	return getPCRValue(index, tpm2.AlgSHA256)
}

func GetPCRSHA384Value(index int) ([]byte, error) {
	return getPCRValue(index, tpm2.AlgSHA384)
}
