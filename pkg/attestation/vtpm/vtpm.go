// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package vtpm

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/absmach/supermq/pkg/errors"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
	"golang.org/x/crypto/sha3"
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
}

func NewVerifier(writer io.Writer) attestation.Verifier {
	return &verifier{
		writer: writer,
	}
}

func (v *verifier) VerifyWithCoRIM(report []byte, manifest *corim.UnsignedCorim) error {
	attestation := &attest.Attestation{}
	if err := proto.Unmarshal(report, attestation); err != nil {
		return fmt.Errorf("failed to unmarshal attestation report: %w", err)
	}

	// Extract measurement from SEV-SNP report if present
	snp := attestation.GetSevSnpAttestation()
	if snp == nil {
		return fmt.Errorf("no SEV-SNP attestation found in report")
	}

	measurement := snp.GetReport().GetMeasurement()
	if len(measurement) == 0 {
		return fmt.Errorf("no measurement in SEV-SNP report")
	}

	// Iterate over CoMIDs tags looking for measurements
	for _, tag := range manifest.Tags {
		// Expecting a CoMID tag
		if !bytes.HasPrefix(tag, corim.ComidTag) {
			continue
		}

		tagValue := tag[len(corim.ComidTag):]

		var c comid.Comid
		if err := c.FromCBOR(tagValue); err != nil {
			return fmt.Errorf("failed to parse CoMID from tag: %w", err)
		}

		// Match measurements in CoMID
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

	// returning nil to satisfy interface for now as we transition
	return nil
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
