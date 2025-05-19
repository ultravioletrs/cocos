// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/absmach/magistrala/pkg/errors"
	"github.com/fatih/color"
	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/proto/check"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/tools/lib/report"
	tpmAttest "github.com/google/go-tpm-tools/proto/attest"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/azure"
	"github.com/ultravioletrs/cocos/pkg/attestation/quoteprovider"
	"github.com/ultravioletrs/cocos/pkg/attestation/vtpm"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	defaultMinimumTcb       = 0
	defaultMinimumLaunchTcb = 0
	defaultMinimumGuestSvn  = 0
	defaultGuestPolicy      = 0x0000000000030000
	defaultMinimumBuild     = 0
	defaultCheckCrl         = false
	defaultTimeout          = 2 * time.Minute
	defaultMaxRetryDelay    = 30 * time.Second
	defaultRequireAuthor    = false
	defaultRequireIdBlock   = false
	defaultMinVersion       = "0.0"
	size16                  = 16
	size32                  = 32
	size48                  = 48
	size64                  = 64
	attestationFilePath     = "attestation.bin"
	vtpmFilePath            = "../quote.dat"
	attestationJson         = "attestation.json"
	sevProductNameMilan     = "Milan"
	sevProductNameGenoa     = "Genoa"
	FormatBinaryPB          = "binarypb"
	FormatTextProto         = "textproto"
	exampleJSONConfig       = `
	{
		"rootOfTrust":{
		   "product":"test_product",
		   "cabundlePaths":[
			  "test_cabundlePaths"
		   ],
		   "cabundles":[
			  "test_Cabundles"
		   ],
		   "checkCrl":true,
		   "disallowNetwork":true
		},
		"policy":{
		   "minimumGuestSvn":1,
		   "policy":"1",
		   "familyId":"AQIDBAUGBwgJCgsMDQ4PEA==",
		   "imageId":"AQIDBAUGBwgJCgsMDQ4PEA==",
		   "vmpl":0,
		   "minimumTcb":"1",
		   "minimumLaunchTcb":"1",
		   "platformInfo":"1",
		   "requireAuthorKey":true,
		   "reportData":"J+60aXs8btm8VcGgaJYURGeNCu0FIyWMFXQ7ZUlJDC0FJGJizJsOzDIXgQ75UtPC+Zqe0A3dvnnf5VEeQ61RTg==",
		   "measurement":"8s78ewoX7Xkfy1qsgVnkZwLDotD768Nqt6qTL5wtQOxHsLczipKM6bhDmWiHLdP4",
		   "hostData":"GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw=",
		   "reportId":"GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw=",
		   "reportIdMa":"GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw=",
		   "chipId":"J+60aXs8btm8VcGgaJYURGeNCu0FIyWMFXQ7ZUlJDC0FJGJizJsOzDIXgQ75UtPC+Zqe0A3dvnnf5VEeQ61RTg==",
		   "minimumBuild":1,
		   "minimumVersion":"0.90",
		   "permitProvisionalFirmware":true,
		   "requireIdBlock":true,
		   "trustedAuthorKeys":[
			  "GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw="
		   ],
		   "trustedAuthorKeyHashes":[
			  "GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw="
		   ],
		   "trustedIdKeys":[
			  "GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw="
		   ],
		   "trustedIdKeyHashes":[
			  "GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw="
		   ],
		   "product":{
			  "name":"SEV_PRODUCT_MILAN",
			  "stepping":1,
			  "machineStepping":1
		   }
		}
	}
	`
	SNP     = "snp"
	VTPM    = "vtpm"
	SNPvTPM = "snp-vtpm"
	CCNone  = "none"
	CCAzure = "azure"
	CCGCP   = "gcp"
)

var (
	mode                    string
	cfg                     = check.Config{Policy: &check.Policy{}, RootOfTrust: &check.RootOfTrust{}}
	cfgString               string
	timeout                 time.Duration
	maxRetryDelay           time.Duration
	platformInfo            string
	stepping                string
	trustedAuthorKeys       []string
	trustedAuthorHashes     []string
	trustedIdKeys           []string
	trustedIdKeyHashes      []string
	attestationFile         string
	tpmAttestationFile      string
	attestationRaw          []byte
	empty16                 = [size16]byte{}
	empty32                 = [size32]byte{}
	empty64                 = [size64]byte{}
	defaultReportIdMa       = []byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255}
	errReportSize           = errors.New("attestation contents too small")
	ErrBadAttestation       = errors.New("attestation file is corrupted or in wrong format")
	output                  string
	nonce                   []byte
	format                  string
	teeNonce                []byte
	getTextProtoAttestation bool
	cloud                   string
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
		Short:     "Retrieve attestation information from agent. The argument of the command must be the type of the report (snp or vtpm or snp-vtpm).",
		ValidArgs: []cobra.Completion{SNP, VTPM, SNPvTPM},
		Example: fmt.Sprintf(`Based on attestation report type:
		get %s --tee <512 bit hex value>
		get %s --vtpm <256 bit hex value>
		get %s --tee <512 bit hex value> --vtpm <256 bit hex value>`, SNP, VTPM, SNPvTPM),
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

			var fixedReportData [quoteprovider.Nonce]byte
			if attType != attestation.VTPM {
				if len(teeNonce) > quoteprovider.Nonce {
					msg := color.New(color.FgRed).Sprintf("nonce must be a hex encoded string of length lesser or equal %d bytes ❌ ", quoteprovider.Nonce)
					cmd.Println(msg)
					return
				}

				copy(fixedReportData[:], teeNonce)
			}

			var fixedVtpmNonceByte [vtpm.Nonce]byte
			if attType != attestation.SNP {
				if len(nonce) > vtpm.Nonce {
					msg := color.New(color.FgRed).Sprintf("vTPM nonce must be a hex encoded string of length lesser or equal %d bytes ❌ ", vtpm.Nonce)
					cmd.Println(msg)
					return
				}

				copy(fixedVtpmNonceByte[:], nonce)
			}

			filename := attestationFilePath
			if getTextProtoAttestation {
				filename = attestationJson
			}

			attestationFile, err := os.Create(filename)
			if err != nil {
				printError(cmd, "Error creating attestation file: %v ❌ ", err)
				return
			}

			if err := cli.agentSDK.Attestation(cmd.Context(), fixedReportData, fixedVtpmNonceByte, int(attType), attestationFile); err != nil {
				printError(cmd, "Failed to get attestation due to error: %v ❌ ", err)
				return
			}

			if err := attestationFile.Close(); err != nil {
				printError(cmd, "Error closing attestation file: %v ❌ ", err)
				return
			}

			if getTextProtoAttestation {
				result, err := os.ReadFile(filename)
				if err != nil {
					printError(cmd, "Error reading attestation file: %v ❌ ", err)
					return
				}

				switch attestationType {
				case SNP:
					result, err = attesationToJSON(result)
				case VTPM, SNPvTPM:
					marshalOptions := prototext.MarshalOptions{
						Multiline: true,
						EmitASCII: true,
					}
					var attvTPM tpmAttest.Attestation
					err = proto.Unmarshal(result, &attvTPM)
					if err != nil {
						printError(cmd, "failed to unmarshal the attestation report: %v ❌ ", ErrBadAttestation)
					}

					result = []byte(marshalOptions.Format(&attvTPM))
				}

				if err != nil {
					printError(cmd, "Error converting attestation to textproto: %v ❌ ", err)
					return
				}

				if err := os.WriteFile(filename, result, 0o644); err != nil {
					printError(cmd, "Error writing attestation file: %v ❌ ", err)
					return
				}
			}

			cmd.Println("Attestation result retrieved and saved successfully!")
		},
	}

	cmd.Flags().BoolVarP(&getTextProtoAttestation, "textproto", "p", false, "Get attestation in textproto format")
	cmd.Flags().BytesHexVarP(&teeNonce, "tee", "e", []byte{}, "Define the nonce for the SNP attestation report (must be used with attestation type snp and snp-vtpm)")
	cmd.Flags().BytesHexVarP(&nonce, "vtpm", "t", []byte{}, "Define the nonce for the vTPM attestation report (must be used with attestation type vtpm and snp-vtpm)")

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
		Short: fmt.Sprintf("Validate and verify attestation information. You can define the confidential computing cloud provider (%s, %s, %s; %s is the default) and can choose from 3 modes: %s, %s and %s. Default mode is %s.", CCNone, CCAzure, CCGCP, CCNone, SNP, VTPM, SNPvTPM, SNP),
		Example: `Based on mode:
		validate <attestationreportfilepath> --report_data <reportdata> --product <product data> --platform <cc platform> //default
		validate --mode snp <attestationreportfilepath> --report_data <reportdata> --product <product data>
		validate --mode vtpm <attestationreportfilepath> --nonce <noncevalue> --format <formatvalue>  --output <outputvalue>
		validate --mode snp-vtpm <attestationreportfilepath> --report_data <reportdata> --product <product data> --nonce <noncevalue> --format <formatvalue>  --output <outputvalue>
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

			var provider attestation.Provider
			switch cloud {
			case CCNone:
				provider = vtpm.New(nil, false, 0, output)
			case CCAzure:
				provider = azure.New(output)
			case CCGCP:
				provider = vtpm.New(nil, false, 0, output)
			default:
				provider = vtpm.New(nil, false, 0, output)
			}

			switch mode {
			case SNP:
				return sevsnpverify(cmd, provider, args)
			case SNPvTPM:
				return vtpmSevSnpverify(args, provider)
			case VTPM:
				return vtpmverify(args, provider)
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

	// SEV-SNP FLAGS
	cmd.Flags().StringVar(
		&cfgString,
		"config",
		"",
		"Serialized json check.Config protobuf. This will overwrite individual flags. Unmarshalled as json. Example: "+exampleJSONConfig,
	)
	cmd.Flags().BytesHexVar(
		&cfg.Policy.HostData,
		"host_data",
		empty32[:],
		"The expected HOST_DATA field as a hex string. Must encode 32 bytes. Unchecked if unset.",
	)
	cmd.Flags().BytesHexVar(
		&cfg.Policy.ReportData,
		"report_data",
		empty64[:],
		"The expected REPORT_DATA field as a hex string. Must encode 64 bytes. Must be set.",
	)
	cmd.Flags().BytesHexVar(
		&cfg.Policy.FamilyId,
		"family_id",
		empty16[:],
		"The expected FAMILY_ID field as a hex string. Must encode 16 bytes. Unchecked if unset.",
	)
	cmd.Flags().BytesHexVar(
		&cfg.Policy.ImageId,
		"image_id",
		empty16[:],
		"The expected IMAGE_ID field as a hex string. Must encode 16 bytes. Unchecked if unset.",
	)
	cmd.Flags().BytesHexVar(
		&cfg.Policy.ReportId,
		"report_id",
		nil,
		"The expected REPORT_ID field as a hex string. Must encode 32 bytes. Unchecked if unset.",
	)
	cmd.Flags().BytesHexVar(
		&cfg.Policy.ReportIdMa,
		"report_id_ma",
		defaultReportIdMa,
		"The expected REPORT_ID_MA field as a hex string. Must encode 32 bytes. Unchecked if unset.",
	)
	cmd.Flags().BytesHexVar(
		&cfg.Policy.Measurement,
		"measurement",
		nil,
		"The expected MEASUREMENT field as a hex string. Must encode 48 bytes. Unchecked if unset.",
	)
	cmd.Flags().BytesHexVar(
		&cfg.Policy.ChipId,
		"chip_id",
		nil,
		"The expected MEASUREMENT field as a hex string. Must encode 48 bytes. Unchecked if unset.",
	)
	cmd.Flags().Uint64Var(
		&cfg.Policy.MinimumTcb,
		"minimum_tcb",
		defaultMinimumTcb,
		"The minimum acceptable value for CURRENT_TCB, COMMITTED_TCB, and REPORTED_TCB.",
	)
	cmd.Flags().Uint64Var(
		&cfg.Policy.MinimumLaunchTcb,
		"minimum_lauch_tcb",
		defaultMinimumLaunchTcb,
		"The minimum acceptable value for LAUNCH_TCB.",
	)
	cmd.Flags().Uint64Var(
		&cfg.Policy.Policy,
		"guest_policy",
		defaultGuestPolicy,
		"The most acceptable guest SnpPolicy.",
	)
	cmd.Flags().Uint32Var(
		&cfg.Policy.MinimumGuestSvn,
		"minimum_guest_svn",
		defaultMinimumGuestSvn,
		"The most acceptable GUEST_SVN.",
	)
	cmd.Flags().Uint32Var(
		&cfg.Policy.MinimumBuild,
		"minimum_build",
		defaultMinimumBuild,
		"The 8-bit minimum build number for AMD-SP firmware",
	)
	cmd.Flags().BoolVar(
		&cfg.RootOfTrust.CheckCrl,
		"check_crl",
		defaultCheckCrl,
		"Download and check the CRL for revoked certificates.",
	)
	cmd.Flags().DurationVar(
		&timeout,
		"timeout",
		defaultTimeout,
		"Duration to continue to retry failed HTTP requests.",
	)
	cmd.Flags().DurationVar(
		&maxRetryDelay,
		"max_retry_delay",
		defaultMaxRetryDelay,
		"Maximum Duration to wait between HTTP request retries.",
	)
	cmd.Flags().BoolVar(
		&cfg.Policy.RequireAuthorKey,
		"require_author_key",
		defaultRequireAuthor,
		"Require that AUTHOR_KEY_EN is 1.",
	)
	cmd.Flags().BoolVar(
		&cfg.Policy.RequireIdBlock,
		"require_id_block",
		defaultRequireIdBlock,
		"Require that the VM was launch with an ID_BLOCK signed by a trusted id key or author key",
	)
	cmd.Flags().StringVar(
		&platformInfo,
		"platform_info",
		"",
		"The maximum acceptable PLATFORM_INFO field bit-wise. May be empty or a 64-bit unsigned integer",
	)
	cmd.Flags().StringVar(
		&cfg.Policy.MinimumVersion,
		"minimum_version",
		defaultMinVersion,
		"Minimum AMD-SP firmware API version (major.minor). Each number must be 8-bit non-negative.",
	)
	cmd.Flags().StringArrayVar(
		&trustedAuthorKeys,
		"trusted_author_keys",
		[]string{},
		"Paths to x.509 certificates of trusted author keys",
	)
	cmd.Flags().StringArrayVar(
		&trustedAuthorHashes,
		"trusted_author_key_hashes",
		[]string{},
		"Hex-encoded SHA-384 hash values of trusted author keys in AMD public key format",
	)
	cmd.Flags().StringArrayVar(
		&trustedIdKeys,
		"trusted_id_keys",
		[]string{},
		"Paths to x.509 certificates of trusted author keys",
	)
	cmd.Flags().StringArrayVar(
		&trustedIdKeyHashes,
		"trusted_id_key_hashes",
		[]string{},
		"Hex-encoded SHA-384 hash values of trusted identity keys in AMD public key format",
	)
	cmd.Flags().StringVar(
		&cfg.RootOfTrust.ProductLine,
		"product",
		"",
		"The AMD product name for the chip that generated the attestation report.",
	)
	cmd.Flags().StringVar(
		&stepping,
		"stepping",
		"",
		"The machine stepping for the chip that generated the attestation report. Default unchecked.",
	)
	cmd.Flags().StringArrayVar(
		&cfg.RootOfTrust.CabundlePaths,
		"CA_bundles_paths",
		[]string{},
		"Paths to CA bundles for the AMD product. Must be in PEM format, ASK, then ARK certificates. If unset, uses embedded root certificates.",
	)
	cmd.Flags().StringArrayVar(
		&cfg.RootOfTrust.Cabundles,
		"CA_bundles",
		[]string{},
		"PEM format CA bundles for the AMD product. Combined with contents of cabundle_paths.",
	)

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

func sevsnpverify(cmd *cobra.Command, provider attestation.Provider, args []string) error {
	cmd.Println("Checking attestation")

	attestationFile = string(args[0])
	if err := parseAttestationFile(); err != nil {
		return fmt.Errorf("error parsing config: %v ❌ ", err)
	}

	// This format is the attestation report in AMD's specified ABI format, immediately
	// followed by the certificate table bytes.
	if len(attestationRaw) < abi.ReportSize {
		return fmt.Errorf("attestation too small: got 0x%x bytes, need at least 0x%x bytes", len(attestationRaw), abi.ReportSize)
	}

	if err := parseAttestationConfig(); err != nil {
		return err
	}

	// Used for verification of SNP attestation report
	attestation.AttestationPolicy.Config = &cfg

	if err := provider.VerifTeeAttestation(attestationRaw, cfg.Policy.ReportData); err != nil {
		return fmt.Errorf("attestation validation and verification failed with error: %v ❌ ", err)
	}

	cmd.Println("Attestation validation and verification is successful!")
	return nil
}

func parseAttestationConfig() error {
	if err := parseConfig(); err != nil {
		return fmt.Errorf("error parsing config: %v ❌ ", err)
	}
	if err := parseHashes(); err != nil {
		return fmt.Errorf("error parsing hashes: %v ❌ ", err)
	}
	if err := parseTrustedKeys(); err != nil {
		return fmt.Errorf("error parsing files: %v ❌ ", err)
	}

	if err := parseUints(); err != nil {
		return fmt.Errorf("error parsing uints: %v ❌ ", err)
	}

	if err := validateInput(); err != nil {
		return fmt.Errorf("error validating input: %v ❌ ", err)
	}

	return nil
}

func vtpmSevSnpverify(args []string, provider attestation.Provider) error {
	attest, err := returnvTPMAttestation(args)
	if err != nil {
		return err
	}

	if err := parseAttestationConfig(); err != nil {
		return err
	}

	// Used for verification of SNP attestation report
	attestation.AttestationPolicy.Config = &cfg

	if err := provider.VerifyAttestation(attest, cfg.Policy.ReportData, nonce); err != nil {
		return fmt.Errorf("attestation validation and verification failed with error: %v ❌ ", err)
	}

	return nil
}

func vtpmverify(args []string, provider attestation.Provider) error {
	attestation, err := returnvTPMAttestation(args)
	if err != nil {
		return err
	}

	if err := provider.VerifVTpmAttestation(attestation, nonce); err != nil {
		return fmt.Errorf("attestation validation and verification failed with error: %v ❌ ", err)
	}

	return nil
}

func returnvTPMAttestation(args []string) ([]byte, error) {
	tpmAttestationFile = string(args[0])
	input, err := openInputFile()
	if err != nil {
		return nil, err
	}
	if closer, ok := input.(*os.File); ok {
		defer closer.Close()
	}
	attestationBytes, err := io.ReadAll(input)
	if err != nil {
		return nil, err
	}
	attestation := &tpmAttest.Attestation{}

	if format == FormatBinaryPB {
		return attestationBytes, nil
	} else if format == FormatTextProto {
		unmarshalOptions := prototext.UnmarshalOptions{}
		err = unmarshalOptions.Unmarshal(attestationBytes, attestation)
	} else {
		return nil, fmt.Errorf("format should be either binarypb or textproto")
	}
	if err != nil {
		return nil, fmt.Errorf("fail to unmarshal attestation report: %v", err)
	}

	attestationBytes, err = proto.Marshal(attestation)
	if err != nil {
		return nil, fmt.Errorf("fail to marshal vTPM attestation report: %v", err)
	}

	return attestationBytes, nil
}

func openInputFile() (io.Reader, error) {
	if tpmAttestationFile == "" {
		return nil, errEmptyFile
	}
	return os.Open(tpmAttestationFile)
}

func createOutputFile() (io.Writer, error) {
	if output == "" {
		return os.Stdout, nil
	}
	return os.Create(output)
}

// parseConfig decodes config passed as json for check.Config struct.
// example
/* {
	"rootOfTrust":{
		"product":"test_product",
		"cabundlePaths":[
		   "test_cabundlePaths"
		],
		"cabundles":[
		   "test_Cabundles"
		],
		"checkCrl":true,
		"disallowNetwork":true
	 },
	 "policy":{
		"minimumGuestSvn":1,
		"policy":"1",
		"familyId":"AQIDBAUGBwgJCgsMDQ4PEA==",
		"imageId":"AQIDBAUGBwgJCgsMDQ4PEA==",
		"vmpl":0,
		"minimumTcb":"1",
		"minimumLaunchTcb":"1",
		"platformInfo":"1",
		"requireAuthorKey":true,
		"reportData":"J+60aXs8btm8VcGgaJYURGeNCu0FIyWMFXQ7ZUlJDC0FJGJizJsOzDIXgQ75UtPC+Zqe0A3dvnnf5VEeQ61RTg==",
		"measurement":"8s78ewoX7Xkfy1qsgVnkZwLDotD768Nqt6qTL5wtQOxHsLczipKM6bhDmWiHLdP4",
		"hostData":"GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw=",
		"reportId":"GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw=",
		"reportIdMa":"GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw=",
		"chipId":"J+60aXs8btm8VcGgaJYURGeNCu0FIyWMFXQ7ZUlJDC0FJGJizJsOzDIXgQ75UtPC+Zqe0A3dvnnf5VEeQ61RTg==",
		"minimumBuild":1,
		"minimumVersion":"0.90",
		"permitProvisionalFirmware":true,
		"requireIdBlock":true,
		"trustedAuthorKeys":[
		   "GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw="
		],
		"trustedAuthorKeyHashes":[
		   "GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw="
		],
		"trustedIdKeys":[
		   "GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw="
		],
		"trustedIdKeyHashes":[
		   "GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw="
		],
		"product":{
		   "name":"SEV_PRODUCT_MILAN",
		   "stepping":1,
		   "machineStepping":1
		}
	 }
  }*/
func parseConfig() error {
	if cfgString == "" {
		return nil
	}
	if err := protojson.Unmarshal([]byte(cfgString), &cfg); err != nil {
		return err
	}
	// Populate fields that should not be nil
	if cfg.RootOfTrust == nil {
		cfg.RootOfTrust = &check.RootOfTrust{}
	}
	if cfg.Policy == nil {
		cfg.Policy = &check.Policy{}
	}
	return nil
}

func parseHashes() error {
	for _, hash := range trustedAuthorHashes {
		hashBytes, err := hex.DecodeString(hash)
		if err != nil {
			return err
		}
		cfg.Policy.TrustedAuthorKeyHashes = append(cfg.Policy.TrustedAuthorKeyHashes, hashBytes)
	}
	for _, hash := range trustedIdKeyHashes {
		hashBytes, err := hex.DecodeString(hash)
		if err != nil {
			return err
		}
		cfg.Policy.TrustedIdKeyHashes = append(cfg.Policy.TrustedIdKeyHashes, hashBytes)
	}
	return nil
}

func parseAttestationFile() error {
	file, err := os.ReadFile(attestationFile)
	if err != nil {
		return err
	}
	attestationRaw = file
	if isFileJSON(attestationFile) {
		attestationRaw, err = attesationFromJSON(attestationRaw)
		if err != nil {
			return err
		}
	}

	return nil
}

func parseTrustedKeys() error {
	for _, path := range trustedAuthorKeys {
		file, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		cfg.Policy.TrustedAuthorKeys = append(cfg.Policy.TrustedAuthorKeys, file)
	}
	for _, path := range trustedIdKeys {
		file, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		cfg.Policy.TrustedIdKeys = append(cfg.Policy.TrustedIdKeys, file)
	}
	return nil
}

func parseUints() error {
	if stepping != "" {
		if base := getBase(stepping); base == 10 {
			num, err := strconv.ParseUint(stepping, getBase(stepping), 8)
			if err != nil {
				return err
			}
			cfg.Policy.Product.MachineStepping = wrapperspb.UInt32(uint32(num))
		} else {
			num, err := strconv.ParseUint(stepping[2:], base, 8)
			if err != nil {
				return err
			}
			cfg.Policy.Product.MachineStepping = wrapperspb.UInt32(uint32(num))
		}
	}
	if platformInfo != "" {
		if base := getBase(platformInfo); base == 10 {
			num, err := strconv.ParseUint(platformInfo, getBase(platformInfo), 8)
			if err != nil {
				return err
			}
			cfg.Policy.PlatformInfo = wrapperspb.UInt64(num)
		} else {
			num, err := strconv.ParseUint(platformInfo[2:], base, 8)
			if err != nil {
				return err
			}
			cfg.Policy.PlatformInfo = wrapperspb.UInt64(num)
		}
	}
	return nil
}

func getBase(val string) int {
	switch {
	case strings.HasPrefix(val, "0x"):
		return 16
	case strings.HasPrefix(val, "0o"):
		return 8
	case strings.HasPrefix(val, "0b"):
		return 2
	default:
		return 10
	}
}

func validateInput() error {
	if len(cfg.RootOfTrust.CabundlePaths) != 0 || len(cfg.RootOfTrust.Cabundles) != 0 && cfg.RootOfTrust.ProductLine == "" {
		return fmt.Errorf("product name must be set if CA bundles are provided")
	}

	if err := validateFieldLength("report_data", cfg.Policy.ReportData, size64); err != nil {
		return err
	}
	if err := validateFieldLength("host_data", cfg.Policy.HostData, size32); err != nil {
		return err
	}
	if err := validateFieldLength("family_id", cfg.Policy.FamilyId, size16); err != nil {
		return err
	}
	if err := validateFieldLength("image_id", cfg.Policy.ImageId, size16); err != nil {
		return err
	}
	if err := validateFieldLength("report_id", cfg.Policy.ReportId, size32); err != nil {
		return err
	}
	if err := validateFieldLength("report_id_ma", cfg.Policy.ReportIdMa, size32); err != nil {
		return err
	}
	if err := validateFieldLength("measurement", cfg.Policy.Measurement, size48); err != nil {
		return err
	}
	if err := validateFieldLength("chip_id", cfg.Policy.ChipId, size64); err != nil {
		return err
	}
	for _, hash := range cfg.Policy.TrustedAuthorKeyHashes {
		if err := validateFieldLength("trusted_author_key_hash", hash, size48); err != nil {
			return err
		}
	}
	for _, hash := range cfg.Policy.TrustedIdKeyHashes {
		if err := validateFieldLength("trusted_id_key_hash", hash, size48); err != nil {
			return err
		}
	}
	return nil
}

func validateFieldLength(fieldName string, field []byte, expectedLength int) error {
	if field != nil && len(field) != expectedLength {
		return fmt.Errorf("%s length should be at least %d bytes long", fieldName, expectedLength)
	}
	return nil
}
