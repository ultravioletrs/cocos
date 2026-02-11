// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package vtpm

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/absmach/supermq/pkg/errors"
	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/proto/check"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/proto/attest"
	ptpm "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm-tools/server"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/eat"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
)

var (
	_ attestation.Provider = (*provider)(nil)
	_ attestation.Verifier = (*verifier)(nil)
)

const (
	eventLog = "/sys/kernel/security/tpm0/binary_bios_measurements"
	Nonce    = 32
	PCR15    = 15
	PCR16    = 16
	Hash1    = 20
	Hash256  = 32
	Hash384  = 48
)

var (
	ExternalTPM                 io.ReadWriteCloser
	ErrNoHashAlgo               = errors.New("hash algo is not supported")
	ErrFetchQuote               = errors.New("failed to fetch vTPM quote")
	ErrAttestationPolicyOpen    = errors.New("failed to open Attestation Policy file")
	ErrAttestationPolicyDecode  = errors.New("failed to decode Attestation Policy file")
	ErrAttestationPolicyMissing = errors.New("failed due to missing Attestation Policy file")
	ErrProtoMarshalFailed       = errors.New("failed to marshal protojson")
	ErrJsonMarshalFailed        = errors.New("failed to marshal json")
	ErrJsonUnarshalFailed       = errors.New("failed to unmarshal json")
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
	teeAttestaion bool
	vmpl          uint
}

func NewProvider(teeAttestation bool, vmpl uint) attestation.Provider {
	return &provider{
		teeAttestaion: teeAttestation,
		vmpl:          vmpl,
	}
}

func (v provider) Attestation(teeNonce []byte, vTpmNonce []byte) ([]byte, error) {
	return Attest(teeNonce, vTpmNonce, v.teeAttestaion, v.vmpl)
}

func (v provider) TeeAttestation(teeNonce []byte) ([]byte, error) {
	return fetchSEVAttestation(teeNonce, v.vmpl)
}

func (v provider) VTpmAttestation(vTpmNonce []byte) ([]byte, error) {
	quote, err := FetchQuote(vTpmNonce)
	if err != nil {
		return []byte{}, errors.Wrap(ErrFetchQuote, err)
	}

	return proto.Marshal(quote)
}

func (v provider) AzureAttestationToken(tokenNonce []byte) ([]byte, error) {
	return nil, errors.New("Azure attestation token is not supported")
}

type verifier struct {
	writer io.Writer
	Policy *attestation.Config
}

func NewVerifier(writer io.Writer) attestation.Verifier {
	policy := &attestation.Config{
		Config:    &check.Config{Policy: &check.Policy{}, RootOfTrust: &check.RootOfTrust{}},
		PcrConfig: &attestation.PcrConfig{},
	}

	return &verifier{
		writer: writer,
		Policy: policy,
	}
}

func NewVerifierWithPolicy(pubKey []byte, writer io.Writer, policy *attestation.Config) attestation.Verifier {
	if policy == nil {
		return NewVerifier(writer)
	}

	return &verifier{
		writer: writer,
		Policy: policy,
	}
}

func (v verifier) VerifTeeAttestation(report []byte, teeNonce []byte) error {
	attestReport, err := abi.ReportToProto(report)
	if err != nil {
		return errors.Wrap(fmt.Errorf("failed to convert TEE report to proto"), err)
	}

	attestationReport := sevsnp.Attestation{Report: attestReport, CertificateChain: nil}
	return VerifySEVAttestationReportTLS(&attestationReport, teeNonce, v.Policy)
}

func (v verifier) VerifVTpmAttestation(report []byte, vTpmNonce []byte) error {
	return VerifyQuote(report, vTpmNonce, v.writer, v.Policy)
}

func (v verifier) VerifyAttestation(report []byte, teeNonce []byte, vTpmNonce []byte) error {
	return VTPMVerify(report, teeNonce, vTpmNonce, v.writer, v.Policy)
}

func (v *verifier) JSONToPolicy(path string) error {
	return ReadPolicy(path, v.Policy)
}

// VerifyEAT verifies an EAT token and extracts the binary report for verification.
func (v *verifier) VerifyEAT(eatToken []byte, teeNonce []byte, vTpmNonce []byte) error {
	// Decode EAT token
	claims, err := eat.Decode(eatToken, nil)
	if err != nil {
		return fmt.Errorf("failed to decode EAT token: %w", err)
	}

	// Verify the embedded binary report
	return v.VerifyAttestation(claims.RawReport, teeNonce, vTpmNonce)
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

func VTPMVerify(quote []byte, teeNonce []byte, vtpmNonce []byte, writer io.Writer, policy *attestation.Config) error {
	if err := VerifyQuote(quote, vtpmNonce, writer, policy); err != nil {
		return fmt.Errorf("failed to verify vTPM quote: %v", err)
	}

	attestation := &attest.Attestation{}

	err := proto.Unmarshal(quote, attestation)
	if err != nil {
		return errors.Wrap(fmt.Errorf("failed to unmarshal quote"), err)
	}

	akPub := attestation.GetAkPub()

	nonce := make([]byte, 0, len(teeNonce)+len(akPub))
	nonce = append(nonce, teeNonce...)
	nonce = append(nonce, akPub...)

	attestData := sha3.Sum512(nonce)

	if err := VerifySEVAttestationReportTLS(attestation.GetSevSnpAttestation(), attestData[:], policy); err != nil {
		return fmt.Errorf("failed to verify TEE attestation report: %v", err)
	}

	return nil
}

func VerifyQuote(quote []byte, vtpmNonce []byte, writer io.Writer, policy *attestation.Config) error {
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

	verifyOpts := server.VerifyOpts{Nonce: vtpmNonce, TrustedAKs: []crypto.PublicKey{cryptoPub}, AllowEFIAppBeforeCallingEvent: true}

	ms, err := server.VerifyAttestation(attestation, verifyOpts)
	if err != nil {
		return errors.Wrap(fmt.Errorf("failed to verify attestation"), err)
	}

	if err := checkExpectedPCRValues(attestation, policy); err != nil {
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
	akPub := attestation.GetAkPub()

	teeNonce := make([]byte, 0, len(nonce)+len(akPub))
	teeNonce = append(teeNonce, nonce...)
	teeNonce = append(teeNonce, akPub...)

	attestData := sha3.Sum512(teeNonce)

	rawTeeAttestation, err := fetchSEVAttestation(attestData[:], vmpl)
	if err != nil {
		return fmt.Errorf("failed to fetch TEE attestation report: %v", err)
	}

	extReport := &sevsnp.Attestation{}
	err = proto.Unmarshal(rawTeeAttestation, extReport)
	if err != nil {
		return errors.Wrap(fmt.Errorf("failed to unmarshal TEE report proto"), err)
	}
	attestation.TeeAttestation = &attest.Attestation_SevSnpAttestation{
		SevSnpAttestation: extReport,
	}

	return nil
}

func checkExpectedPCRValues(attQuote *attest.Attestation, policy *attestation.Config) error {
	quotes := attQuote.GetQuotes()
	for i := range quotes {
		quote := quotes[i]
		var pcrMap map[string]string

		switch quote.Pcrs.Hash {
		case ptpm.HashAlgo_SHA256:
			pcrMap = policy.PcrConfig.PCRValues.Sha256
		case ptpm.HashAlgo_SHA384:
			pcrMap = policy.PcrConfig.PCRValues.Sha384
		case ptpm.HashAlgo_SHA1:
			pcrMap = policy.PcrConfig.PCRValues.Sha1
		default:
			return errors.Wrap(ErrNoHashAlgo, fmt.Errorf("algo: %s", ptpm.HashAlgo_name[int32(quote.Pcrs.Hash)]))
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

func ReadPolicy(policyPath string, attestationConfiguration *attestation.Config) error {
	if policyPath != "" {
		policyData, err := os.ReadFile(policyPath)
		if err != nil {
			return errors.Wrap(ErrAttestationPolicyOpen, err)
		}

		return ReadPolicyFromByte(policyData, attestationConfiguration)
	}

	return ErrAttestationPolicyMissing
}

func ReadPolicyFromByte(policyData []byte, attestationConfiguration *attestation.Config) error {
	unmarshalOptions := protojson.UnmarshalOptions{AllowPartial: true, DiscardUnknown: true}

	if err := unmarshalOptions.Unmarshal(policyData, attestationConfiguration.Config); err != nil {
		return errors.Wrap(ErrAttestationPolicyDecode, err)
	}

	if err := json.Unmarshal(policyData, attestationConfiguration.PcrConfig); err != nil {
		return errors.Wrap(ErrAttestationPolicyDecode, err)
	}

	return nil
}

func ConvertPolicyToJSON(attestationConfiguration *attestation.Config) ([]byte, error) {
	pbJson, err := protojson.Marshal(attestationConfiguration.Config)
	if err != nil {
		return nil, errors.Wrap(ErrProtoMarshalFailed, err)
	}

	var pbMap map[string]any
	if err := json.Unmarshal(pbJson, &pbMap); err != nil {
		return nil, errors.Wrap(ErrJsonUnarshalFailed, err)
	}

	pcrJson, err := json.Marshal(attestationConfiguration.PcrConfig)
	if err != nil {
		return nil, errors.Wrap(ErrJsonMarshalFailed, err)
	}

	var pcrMap map[string]any
	if err := json.Unmarshal(pcrJson, &pcrMap); err != nil {
		return nil, errors.Wrap(ErrJsonUnarshalFailed, err)
	}

	for k, v := range pcrMap {
		pbMap[k] = v
	}

	return json.MarshalIndent(pbMap, "", "  ")
}
