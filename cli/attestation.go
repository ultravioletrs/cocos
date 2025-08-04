// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/absmach/supermq/pkg/errors"
	"github.com/fatih/color"
	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/tools/lib/report"
	tpmAttest "github.com/google/go-tpm-tools/proto/attest"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/azure"
	"github.com/ultravioletrs/cocos/pkg/attestation/quoteprovider"
	"github.com/ultravioletrs/cocos/pkg/attestation/tdx"
	"github.com/ultravioletrs/cocos/pkg/attestation/vtpm"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
)

const (
	size8                     = 8
	size16                    = 16
	size32                    = 32
	size48                    = 48
	size64                    = 64
	attestationFilePath       = "attestation.bin"
	azureAttestResultFilePath = "azure_attest_result.json"
	azureAttestTokenFilePath  = "azure_attest_token.jwt"
	TEE                       = "tee"
	SNP                       = "snp"
	VTPM                      = "vtpm"
	SNPvTPM                   = "snp-vtpm"
	AzureToken                = "azure-token"
	CCNone                    = "none"
	CCAzure                   = "azure"
	CCGCP                     = "gcp"
	TDX                       = "tdx"
)

var (
	mode                          string
	cfgString                     string
	timeout                       time.Duration
	maxRetryDelay                 time.Duration
	platformInfo                  string
	stepping                      string
	trustedAuthorKeys             []string
	trustedAuthorHashes           []string
	trustedIdKeys                 []string
	trustedIdKeyHashes            []string
	attestationFile               string
	attestationRaw                []byte
	empty16                       = [size16]byte{}
	empty32                       = [size32]byte{}
	empty64                       = [size64]byte{}
	defaultReportIdMa             = []byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255}
	errReportSize                 = errors.New("attestation contents too small")
	ErrBadAttestation             = errors.New("attestation file is corrupted or in wrong format")
	output                        string
	nonce                         []byte
	format                        string
	teeNonce                      []byte
	tokenNonce                    []byte
	getTextProtoAttestationReport bool
	getAzureTokenJWT              bool
	cloud                         string
	reportData                    []byte
	checkCrl                      bool
)

var errEmptyFile = errors.New("input file is empty")

func (cli *CLI) NewAttestationCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "attestation [command]",
		Short: "Get and validate attestations",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Printf("Get and validate attestations\n\n")
			cmd.Printf("Usage:\n  %s [command]\n\n", cmd.CommandPath())
			cmd.Printf("Available Commands:\n")

			// Filter out "completion" command
			availableCommands := make([]*cobra.Command, 0)
			for _, subCmd := range cmd.Commands() {
				if subCmd.Name() != "completion" {
					availableCommands = append(availableCommands, subCmd)
				}
			}

			for _, subCmd := range availableCommands {
				cmd.Printf("  %-15s%s\n", subCmd.Name(), subCmd.Short)
			}

			cmd.Printf("\nFlags:\n")
			cmd.Flags().VisitAll(func(flag *pflag.Flag) {
				cmd.Printf("  -%s, --%s %s\n", flag.Shorthand, flag.Name, flag.Usage)
			})
			cmd.Printf("\nUse \"%s [command] --help\" for more information about a command.\n", cmd.CommandPath())
		},
	}
}

func (cli *CLI) NewGetAttestationCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:       "get",
		Short:     "Retrieve attestation information from agent. The argument of the command must be the type of the report (snp or vtpm or snp-vtpm or tdx).",
		ValidArgs: []cobra.Completion{SNP, VTPM, SNPvTPM, AzureToken, TDX},
		Example: fmt.Sprintf(`Based on attestation report type:
		get %s --tee <512 bit hex value>
		get %s --vtpm <256 bit hex value>
		get %s --tee <512 bit hex value> --vtpm <256 bit hex value>
		get %s --token <256 bit hex value>
		get %s --tee <512 bit hex value>`, SNP, VTPM, SNPvTPM, AzureToken, TDX),
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if cli.connectErr != nil {
				printError(cmd, "Failed to connect to agent: %v ❌ ", cli.connectErr)
				return
			}

			if err := cobra.OnlyValidArgs(cmd, args); err != nil {
				printError(cmd, "Bad attestation type: %v ❌ ", err)
				return
			}

			attestationType := args[0]

			attType := attestation.SNP
			switch attestationType {
			case SNP:
				cmd.Println("Fetching SEV-SNP attestation report")
			case VTPM:
				cmd.Println("Fetching vTPM report")
				attType = attestation.VTPM
			case SNPvTPM:
				cmd.Println("Fetching SEV-SNP and vTPM report")
				attType = attestation.SNPvTPM
			case AzureToken:
				cmd.Println("Fetching Azure token")
				attType = attestation.AzureToken
			case TDX:
				cmd.Println("Fetching TDX attestation report")
				attType = attestation.TDX
			}

			if (attType == attestation.VTPM || attType == attestation.SNPvTPM) && len(nonce) == 0 {
				msg := color.New(color.FgRed).Sprint("vTPM nonce must be defined for vTPM attestation ❌ ")
				cmd.Println(msg)
				return
			}

			if (attType == attestation.SNP || attType == attestation.SNPvTPM) && len(teeNonce) == 0 {
				msg := color.New(color.FgRed).Sprint("TEE nonce must be defined for SEV-SNP attestation ❌ ")
				cmd.Println(msg)
				return
			}

			if (attType == attestation.AzureToken) && len(tokenNonce) == 0 {
				msg := color.New(color.FgRed).Sprint("Token nonce must be defined for Azure attestation ❌ ")
				cmd.Println(msg)
				return
			}

			var fixedReportData [quoteprovider.Nonce]byte
			if attType == attestation.SNP || attType == attestation.SNPvTPM {
				if len(teeNonce) > quoteprovider.Nonce {
					msg := color.New(color.FgRed).Sprintf("nonce must be a hex encoded string of length lesser or equal %d bytes ❌ ", quoteprovider.Nonce)
					cmd.Println(msg)
					return
				}

				copy(fixedReportData[:], teeNonce)
			}

			var fixedVtpmNonceByte [vtpm.Nonce]byte
			if attType != attestation.SNP {
				if (len(nonce) > vtpm.Nonce) || (len(tokenNonce) > vtpm.Nonce) {
					msg := color.New(color.FgRed).Sprintf("vTPM nonce must be a hex encoded string of length lesser or equal %d bytes ❌ ", vtpm.Nonce)
					cmd.Println(msg)
					return
				}
				if attType == attestation.AzureToken {
					copy(fixedVtpmNonceByte[:], tokenNonce)
				} else {
					copy(fixedVtpmNonceByte[:], nonce)
				}
			}

			filename := attestationFilePath

			if attType == attestation.AzureToken {
				filename = azureAttestResultFilePath
			}

			if getTextProtoAttestationReport {
				filename = attestationReportJson
			} else if getAzureTokenJWT {
				filename = azureAttestTokenFilePath
			}

			attestationFile, err := os.Create(filename)
			if err != nil {
				printError(cmd, "Error creating attestation file: %v ❌ ", err)
				return
			}

			var returnJsonAzureToken bool

			if attType == attestation.AzureToken {
				err := cli.agentSDK.AttestationResult(cmd.Context(), fixedVtpmNonceByte, int(attType), attestationFile)
				if err != nil {
					printError(cmd, "Failed to get attestation result due to error: %v ❌", err)
					return
				}
				returnJsonAzureToken = !getAzureTokenJWT
			} else {
				err := cli.agentSDK.Attestation(cmd.Context(), fixedReportData, fixedVtpmNonceByte, int(attType), attestationFile)
				if err != nil {
					printError(cmd, "Failed to get attestation due to error: %v ❌", err)
					return
				}
			}

			if err := attestationFile.Close(); err != nil {
				printError(cmd, "Error closing attestation file: %v ❌ ", err)
				return
			}

			if getTextProtoAttestationReport || returnJsonAzureToken {
				result, err := os.ReadFile(filename)
				if err != nil {
					printError(cmd, "Error reading attestation file: %v ❌ ", err)
					return
				}

				switch attestationType {
				case SNP:
					result, err = attesationToJSON(result)
					if err != nil {
						printError(cmd, "Error converting SNP attestation to JSON: %v ❌", err)
						return
					}

				case VTPM, SNPvTPM:
					marshalOptions := prototext.MarshalOptions{
						Multiline: true,
						EmitASCII: true,
					}
					var attvTPM tpmAttest.Attestation
					err = proto.Unmarshal(result, &attvTPM)
					if err != nil {
						printError(cmd, "Failed to unmarshal the attestation report: %v ❌", err)
						return
					}
					result = []byte(marshalOptions.Format(&attvTPM))

				case AzureToken:
					result, err = decodeJWTToJSON(result)
					if err != nil {
						printError(cmd, "Error decoding Azure token: %v ❌", err)
						return
					}
				}

				if err := os.WriteFile(filename, result, 0o644); err != nil {
					printError(cmd, "Error writing attestation file: %v ❌ ", err)
					return
				}
			}

			cmd.Println("Attestation result retrieved and saved successfully!")
		},
	}

	cmd.Flags().BoolVarP(&getAzureTokenJWT, "azurejwt", "t", false, "Get azure attestation token as jwt format")
	cmd.Flags().BoolVarP(&getTextProtoAttestationReport, "reporttextproto", "r", false, "Get attestation report in textproto format")
	cmd.Flags().BytesHexVar(&teeNonce, "tee", []byte{}, "Define the nonce for the SNP and TDX attestation report (must be used with attestation type snp, snp-vtpm, and tdx)")
	cmd.Flags().BytesHexVar(&nonce, "vtpm", []byte{}, "Define the nonce for the vTPM attestation report (must be used with attestation type vtpm and snp-vtpm)")
	cmd.Flags().BytesHexVar(&tokenNonce, "token", []byte{}, "Define the nonce for the Azure attestation token (must be used with attestation type azure-token)")

	return cmd
}

func attesationToJSON(report []byte) ([]byte, error) {
	if len(report) < abi.ReportSize {
		return nil, errors.Wrap(errReportSize, fmt.Errorf("attestation contents too small (0x%x bytes). Want at least 0x%x bytes", len(report), abi.ReportSize))
	}
	attestationPB, err := abi.ReportCertsToProto(report[:abi.ReportSize])
	if err != nil {
		return nil, err
	}

	return json.MarshalIndent(attestationPB, "", "	")
}

func attesationFromJSON(reportFile []byte) ([]byte, error) {
	var attestationPB sevsnp.Attestation
	if err := json.Unmarshal(reportFile, &attestationPB); err != nil {
		return nil, err
	}

	return report.Transform(&attestationPB, "bin")
}

func isFileJSON(filename string) bool {
	return strings.HasSuffix(filename, ".json")
}

func (cli *CLI) NewValidateAttestationValidationCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate",
		Short: fmt.Sprintf("Validate and verify attestation information. You can define the confidential computing cloud provider (%s, %s, %s; %s is the default) and can choose from 4 modes: %s, %s, %s, and %s. Default mode is %s.", CCNone, CCAzure, CCGCP, CCNone, SNP, VTPM, SNPvTPM, TDX, SNP),
		Example: `Based on mode:
		validate <attestationreportfilepath> --report_data <reportdata> --product <product data> --platform <cc platform> //default
		validate --mode snp <attestationreportfilepath> --report_data <reportdata> --product <product data>
		validate --mode vtpm <attestationreportfilepath> --nonce <noncevalue> --format <formatvalue>  --output <outputvalue>
		validate --mode snp-vtpm <attestationreportfilepath> --report_data <reportdata> --product <product data> --nonce <noncevalue> --format <formatvalue>  --output <outputvalue>
		validate --mode tdx <attestationreportfilepath> --report_data <reportdata>
		validate --cloud none --mode snp <attestationreportfilepath> --report_data <reportdata> --product <product data>
		validate --cloud azure --mode vtpm <attestationreportfilepath> --nonce <noncevalue> --format <formatvalue>  --output <outputvalue>
		validate --cloud gcp --mode snp-vtpm <attestationreportfilepath> --report_data <reportdata> --product <product data> --nonce <noncevalue> --format <formatvalue>  --output <outputvalue>`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			mode, _ := cmd.Flags().GetString("mode")
			if len(args) != 1 {
				return fmt.Errorf("please pass the attestation report file path")
			}

			// Validate flags based on the mode
			switch mode {
			case SNP:
				if err := cmd.MarkFlagRequired("report_data"); err != nil {
					return fmt.Errorf("failed to mark 'report_data' as required for SEV-%s mode: %v", SNP, err)
				}
				if err := cmd.MarkFlagRequired("product"); err != nil {
					return fmt.Errorf("failed to mark flag as required: %v ❌ ", err)
				}
			case SNPvTPM:
				if err := cmd.MarkFlagRequired("nonce"); err != nil {
					return fmt.Errorf("failed to mark 'nonce' as required for %s mode: %v", VTPM, err)
				}
				if err := cmd.MarkFlagRequired("report_data"); err != nil {
					return fmt.Errorf("failed to mark 'report_data' as required for SEV-%s mode: %v", SNP, err)
				}
				if err := cmd.MarkFlagRequired("product"); err != nil {
					return fmt.Errorf("failed to mark flag as required: %v ❌ ", err)
				}
				if err := cmd.MarkFlagRequired("format"); err != nil {
					return fmt.Errorf("failed to mark 'format' as required for %s mode: %v", VTPM, err)
				}
				if err := cmd.MarkFlagRequired("output"); err != nil {
					return fmt.Errorf("failed to mark 'output' as required for %s mode: %v", VTPM, err)
				}
			case VTPM:
				if err := cmd.MarkFlagRequired("nonce"); err != nil {
					return fmt.Errorf("failed to mark 'nonce' as required for %s mode: %v", VTPM, err)
				}
				if err := cmd.MarkFlagRequired("format"); err != nil {
					return fmt.Errorf("failed to mark 'format' as required for %s mode: %v", VTPM, err)
				}
				if err := cmd.MarkFlagRequired("output"); err != nil {
					return fmt.Errorf("failed to mark 'output' as required for %s mode: %v", VTPM, err)
				}
			case TDX:
				if err := cmd.MarkFlagRequired("report_data"); err != nil {
					return fmt.Errorf("failed to mark 'report_data' as required for %s mode: %v", TDX, err)
				}
			default:
				return fmt.Errorf("unknown mode: %s", mode)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			mode, _ := cmd.Flags().GetString("mode")
			cloud, _ := cmd.Flags().GetString("cloud")

			output, err := createOutputFile()
			if err != nil {
				return fmt.Errorf("failed to create output file: %v ❌ ", err)
			}
			if closer, ok := output.(*os.File); ok {
				defer closer.Close()
			}

			var verifier attestation.Verifier
			switch cloud {
			case CCNone:
				policy := attestation.Config{Config: &cfg, PcrConfig: &attestation.PcrConfig{}}
				verifier = vtpm.NewVerifierWithPolicy(nil, output, &policy)
			case CCAzure:
				policy := attestation.Config{Config: &cfg, PcrConfig: &attestation.PcrConfig{}}
				verifier = azure.NewVerifierWithPolicy(output, &policy)
			case CCGCP:
				policy := attestation.Config{Config: &cfg, PcrConfig: &attestation.PcrConfig{}}
				verifier = vtpm.NewVerifierWithPolicy(nil, output, &policy)
			default:
				policy := attestation.Config{Config: &cfg, PcrConfig: &attestation.PcrConfig{}}
				verifier = vtpm.NewVerifierWithPolicy(nil, output, &policy)
			}

			switch mode {
			case SNP:
				cfg.Policy.ReportData = reportData
				return sevsnpverify(cmd, verifier, args)
			case SNPvTPM:
				cfg.Policy.ReportData = reportData
				return vtpmSevSnpverify(args, verifier)
			case VTPM:
				cfg.Policy.ReportData = reportData
				return vtpmverify(args, verifier)
			case TDX:
				if err := validateTDXFlags(); err != nil {
					return fmt.Errorf("failed to verify TDX validation flags: %v ❌ ", err)
				}
				verifier = tdx.NewVerifierWithPolicy(cfgTDX)
				return tdxVerify(args[0], verifier)
			default:
				return fmt.Errorf("unknown mode: %s", mode)
			}
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.Flags().StringVar(
		&cloud,
		"cloud",
		"none", // default CC provider
		"The confidential computing cloud provider. Example: azure",
	)

	cmd.Flags().StringVar(
		&mode,
		"mode",
		"snp", // default mode
		"The attestation validation mode. Example: snp",
	)

	// VTPM FLAGS
	cmd.Flags().BytesHexVar(
		&nonce,
		"nonce",
		[]byte{},
		"hex encoded nonce for vTPM attestation, cannot be empty",
	)

	cmd.Flags().StringVar(
		&format,
		"format",
		"binarypb", // default value
		"type of output file where attestation report stored <binarypb|textproto>",
	)

	cmd.Flags().StringVar(
		&output,
		"output",
		"",
		"output file",
	)

	cmd.Flags().StringVar(
		&cfgString,
		"config",
		"",
		"Path to the serialized json check.Config protobuf file. This will overwrite individual flags. Unmarshalled as json. Example: "+exampleJSONConfig,
	)
	cmd.Flags().BytesHexVar(
		&reportData,
		"report_data",
		empty64[:],
		"The expected REPORT_DATA field as a hex string. Must encode 64 bytes. Must be set.",
	)

	cmd = addSEVSNPVerificationOptions(cmd)
	cmd = addTDXVerificationOptions(cmd)

	return cmd
}

func (cli *CLI) NewMeasureCmd(igvmBinaryPath string) *cobra.Command {
	igvmmeasureCmd := &cobra.Command{
		Use:   "igvmmeasure <INPUT>",
		Short: "Measure an IGVM file",
		Long: `igvmmeasure measures an IGVM file and outputs the calculated measurement.
			It ensures integrity verification for the IGVM file.`,

		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("error: No input file provided")
			}

			inputFile := args[0]

			measurement, err := cli.measurement.Run(inputFile)
			if err != nil {
				return err
			}

			outputString := string(measurement)
			lines := strings.Split(strings.TrimSpace(outputString), "\n")

			if len(lines) == 1 {
				outputString = strings.ToLower(outputString)
			} else {
				return fmt.Errorf("error: %s", outputString)
			}

			cmd.Print(outputString)

			return nil
		},
	}

	return igvmmeasureCmd
}

func openInputFile() (io.Reader, error) {
	if attestationFile == "" {
		return nil, errEmptyFile
	}
	return os.Open(attestationFile)
}

func createOutputFile() (io.Writer, error) {
	if output == "" {
		return os.Stdout, nil
	}
	return os.Create(output)
}

func validateFieldLength(fieldName string, field []byte, expectedLength int) error {
	if field != nil && len(field) != expectedLength {
		return fmt.Errorf("%s length should be at least %d bytes long", fieldName, expectedLength)
	}
	return nil
}

func decodeJWTToJSON(tokenBytes []byte) ([]byte, error) {
	token := string(tokenBytes) // convert to string
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid JWT: must have at least 2 parts")
	}

	decode := func(seg string) (map[string]interface{}, error) {
		// Add padding if missing
		if m := len(seg) % 4; m != 0 {
			seg += strings.Repeat("=", 4-m)
		}

		data, err := base64.URLEncoding.DecodeString(seg)
		if err != nil {
			return nil, err
		}

		var result map[string]interface{}
		if err := json.Unmarshal(data, &result); err != nil {
			return nil, err
		}

		return result, nil
	}

	header, err := decode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %v", err)
	}

	payload, err := decode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %v", err)
	}

	combined := map[string]interface{}{
		"header":  header,
		"payload": payload,
	}

	return json.MarshalIndent(combined, "", "  ")
}
