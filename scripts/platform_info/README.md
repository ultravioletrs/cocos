# Rust project for fetching platform info
This rust project fetches information from the host system needed for validation of the attestation report. It outputs a JSON file that contains the said information.
The JSON file is in a format that can be used with the [go-sev-guest](https://github.com/google/go-sev-guest) library.

## Usage
Clone `cocos` repository:
```bash
git clone git@github.com:ultravioletrs/cocos.git
cd ./cocos/scripts/platform_info 
make
```

Then run the binary. Keep in mind that you have to specify the policy of the Guest VM:
```bash
cd ./target/releas

# Run with option --policy (policy is 64 bit number) 
./platform_info --policy 196608
```