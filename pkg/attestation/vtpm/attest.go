package vtpm

import (
	"fmt"
	"io"
	"os"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-tpm-tools/client"
	pb "github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/ultravioletrs/cocos/pkg/attestation/quoteprovider"
	"google.golang.org/protobuf/proto"
)

const (
	eventLog    = "/sys/kernel/security/tpm0/binary_bios_measurements"
	NonceLength = 16
	PCR15       = 15
	PCR16       = 16
)

type tpmWrapper struct {
	io.ReadWriteCloser
}

func (et tpmWrapper) EventLog() ([]byte, error) {
	return os.ReadFile(eventLog)
}

func OpenTpm() (io.ReadWriteCloser, error) {
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

func Attest(nonce []byte, teeAttestaion bool) ([]byte, error) {
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

	var fixedNonce [NonceLength]byte
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

	if teeAttestaion {
		rawTeeAttestation, err := quoteprovider.FetchAttestation(nonce)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch SEV-SNP attestation report")
		}

		extReport, err := abi.ReportCertsToProto(rawTeeAttestation)
		if err != nil {
			return nil, err
		}
		attestation.TeeAttestation = &pb.Attestation_SevSnpAttestation{
			SevSnpAttestation: extReport,
		}
	}

	out, err := proto.Marshal(attestation)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal vTPM attestation report: %v", err)
	}

	return out, nil
}
