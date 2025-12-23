package main

import (
	"encoding/hex"
	"os"

	ccpb "github.com/google/go-tdx-guest/proto/checkconfig"
	"google.golang.org/protobuf/encoding/protojson"
)

var (
	SGXVendorID  = []byte{0x93, 0x9A, 0x72, 0x33, 0xF7, 0x9C, 0x4C, 0xA9, 0x94, 0x0A, 0x0D, 0xB3, 0x95, 0x7F, 0x06, 0x07}
	MinTdxSvn    = []byte{0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	MrSeam       = "5b38e33a6487958b72c3c12a938eaa5e3fd4510c51aeeab58c7d5ecee41d7c436489d6c8e4f92f160b7cad34207b00c1"
	TdAttributes = []byte{
		0x00, 0x00, 0x00, 0x10,
		0x00, 0x00, 0x00, 0x00,
	}
	Xfam = []byte{
		0xe7, 0x02, 0x06, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	MrTd = []byte{
		0x91, 0xeb, 0x2b, 0x44, 0xd1, 0x41, 0xd4, 0xec,
		0xe0, 0x9f, 0x0c, 0x75, 0xc2, 0xc5, 0x3d, 0x24,
		0x7a, 0x3c, 0x68, 0xed, 0xd7, 0xfa, 0xfe, 0x8a,
		0x35, 0x20, 0xc9, 0x42, 0xa6, 0x04, 0xa4, 0x07,
		0xde, 0x03, 0xae, 0x6d, 0xc5, 0xf8, 0x7f, 0x27,
		0x42, 0x8b, 0x25, 0x38, 0x87, 0x31, 0x18, 0xb7,
	}
	rtmr = []string{
		"ce0891f46a18db93e7691f1cf73ed76593f7dec1b58f0927ccb56a99242bf63bc9551561f9ee7833d40395fae59547ab",
		"062ac322e26b10874a84977a09735408a856aec77ff62b4975b1e90e33c18f05220ea522cdbffc3b2cf4451cc209e418",
		"5fd86e8c3d5e45386f1ed0852de7e83ae1b774ee4366bd5213c9890e8e3ac8fad3f7e690891d37f7c81ac20a445cc0ff",
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	}
)

func main() {
	cfgTdx := &ccpb.Config{
		RootOfTrust: &ccpb.RootOfTrust{},
		Policy:      &ccpb.Policy{HeaderPolicy: &ccpb.HeaderPolicy{}, TdQuoteBodyPolicy: &ccpb.TDQuoteBodyPolicy{}},
	}

	cfgTdx.RootOfTrust.CheckCrl = true
	cfgTdx.RootOfTrust.GetCollateral = true

	cfgTdx.Policy.HeaderPolicy.QeVendorId = SGXVendorID
	cfgTdx.Policy.TdQuoteBodyPolicy.MinimumTeeTcbSvn = MinTdxSvn

	seam, err := hex.DecodeString(MrSeam)
	if err != nil {
		panic(err)
	}

	cfgTdx.Policy.TdQuoteBodyPolicy.MrSeam = seam
	cfgTdx.Policy.TdQuoteBodyPolicy.TdAttributes = TdAttributes
	cfgTdx.Policy.TdQuoteBodyPolicy.Xfam = Xfam
	cfgTdx.Policy.TdQuoteBodyPolicy.MrTd = MrTd

	for _, reg := range rtmr {
		r, err := hex.DecodeString(reg)
		if err != nil {
			panic(err)
		}
		cfgTdx.Policy.TdQuoteBodyPolicy.Rtmrs = append(cfgTdx.Policy.TdQuoteBodyPolicy.Rtmrs, r)
	}
	marshaler := protojson.MarshalOptions{
		Multiline: true,
		Indent:    "  ",
	}
	tdxPolicy, err := marshaler.Marshal(cfgTdx)
	if err != nil {
		panic(err)
	}

	err = os.WriteFile("tdx_policy.json", tdxPolicy, 0644)
	if err != nil {
		panic(err)
	}

	_, err = os.Stdout.Write(tdxPolicy)
	if err != nil {
		panic(err)
	}

	Policy := &ccpb.Config{
		RootOfTrust: &ccpb.RootOfTrust{},
		Policy:      &ccpb.Policy{HeaderPolicy: &ccpb.HeaderPolicy{}, TdQuoteBodyPolicy: &ccpb.TDQuoteBodyPolicy{}},
	}

	if err := ReadTDXAttestationPolicy("/home/cocosai/work/test/tdxpolicy/tdx_policy.json", Policy); err != nil {
		panic(err)
	}

}

func ReadTDXAttestationPolicy(policyPath string, policy *ccpb.Config) error {
	policyByte, err := os.ReadFile(policyPath)
	if err != nil {
		return err
	}

	if err := protojson.Unmarshal(policyByte, policy); err != nil {
		return err
	}

	// fmt.Print("Read TDX Attestation Policy:\n")
	// fmt.Printf(policy.String())

	return nil
}
