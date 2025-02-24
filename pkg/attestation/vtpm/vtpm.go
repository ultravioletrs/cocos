// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package vtpm

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"io"
	"os"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-tpm-tools/client"
	pb "github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm-tools/server"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/ultravioletrs/cocos/pkg/attestation/quoteprovider"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"
)

const (
	eventLog = "/sys/kernel/security/tpm0/binary_bios_measurements"
	Nonce    = 32
	PCR15    = 15
)

var ExternalTPM io.ReadWriteCloser

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

	if err := tpm2.PCRExtend(rwc, tpmutil.Handle(pcrIndex), tpm2.AlgSHA256, value, ""); err != nil {
		return err
	}

	if err := tpm2.PCRExtend(rwc, tpmutil.Handle(pcrIndex), tpm2.AlgSHA384, value, ""); err != nil {
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
	attestation := &pb.Attestation{}

	err := proto.Unmarshal(quote, attestation)
	if err != nil {
		return fmt.Errorf("fail to unmarshal quote: %v", err)
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
		return fmt.Errorf("fail to calculate report data: %v", err)
	}

	if err := quoteprovider.VerifyAttestationReportTLS(attestation.GetSevSnpAttestation(), reportData); err != nil {
		return fmt.Errorf("failed to verify TEE attestation report: %v", err)
	}

	_, err = server.VerifyAttestation(attestation, server.VerifyOpts{Nonce: vtpmNonce, TrustedAKs: []crypto.PublicKey{cryptoPub}})
	if err != nil {
		return fmt.Errorf("verifying attestation: %w", err)
	}

	return nil
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

func marshalQuote(attestation *pb.Attestation) ([]byte, error) {
	out, err := proto.Marshal(attestation)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to marshal vTPM attestation report: %v", err)
	}

	return out, nil
}

func fetchVTPMQuote(nonce []byte) (*pb.Attestation, error) {
	rwc, err := OpenTpm()
	if err != nil {
		return nil, err
	}
	defer rwc.Close()

	attestationKey, err := client.AttestationKeyRSA(rwc)
	if err != nil {
		return nil, fmt.Errorf("failed to create attestation key: %v", err)
	}
	defer attestationKey.Close()

	var fixedNonce [Nonce]byte
	copy(fixedNonce[:], nonce)
	attestOpts := client.AttestOpts{}
	attestOpts.Nonce = fixedNonce[:]

	attestOpts.TCGEventLog, err = client.GetEventLog(rwc)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve TCG Event Log: %w", err)
	}

	attestation, err := attestationKey.Attest(attestOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to collect attestation report: %v", err)
	}

	return attestation, nil
}

func addTEEAttestation(attestation *pb.Attestation, nonce []byte) (*pb.Attestation, error) {
	rawTeeAttestation, err := quoteprovider.FetchAttestation(nonce)
	if err != nil {
		return attestation, fmt.Errorf("failed to fetch TEE attestation report: %v", err)
	}

	extReport, err := abi.ReportCertsToProto(rawTeeAttestation)
	if err != nil {
		return attestation, fmt.Errorf("failed to export the TEE report: %v", err)
	}
	attestation.TeeAttestation = &pb.Attestation_SevSnpAttestation{
		SevSnpAttestation: extReport,
	}

	return attestation, nil
}
