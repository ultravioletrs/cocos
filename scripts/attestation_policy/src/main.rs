use base64::prelude::*;
use clap::{value_parser, Arg, Command};
use serde::Serialize;
use sev::firmware::host::*;
use std::arch::x86_64::__cpuid;
use std::fs::File;
use std::io::Write;

const ATTESTATION_POLICY_JSON: &str = "attestation_policy.json";
const EXTENDED_FAMILY_SHIFT: u32 = 20;
const EXTENDED_MODEL_SHIFT: u32 = 16;
const FAMILY_SHIFT: u32 = 8;
const SEV_EXTENDED_FAMILY: u32 = 0xA;
const SEV_FAMILY: u32 = 0xF;
const MILAN_EXTENDED_MODEL: u32 = 0x0;
const GENOA_EXTENDED_MODEL: u32 = 0x1;

const SEV_PRODUCT_UNKNOWN: i32 = 0;
const SEV_PRODUCT_MILAN: i32 = 1;
const SEV_PRODUCT_GENOA: i32 = 2;

#[derive(Clone, Copy, Serialize)]
struct SevProduct {
    name: i32,
}

#[derive(Serialize)]
struct SnpPolicy {
    policy: u64,
    family_id: String,
    image_id: String,
    vmpl: u32,
    minimum_tcb: u64,
    minimum_launch_tcb: u64,
    require_author_key: bool,
    measurement: String,
    host_data: String,
    report_id_ma: String,
    chip_id: String,
    minimum_build: u32,
    minimum_version: String,
    permit_provisional_firmware: bool,
    require_id_block: bool,
    product: SevProduct,
}

#[derive(Serialize)]
struct RootOfTrust {
    product: String,
    check_crl: bool,
    disallow_network: bool,
    product_line: String,
}

#[derive(Serialize)]
struct Computation {
    policy: SnpPolicy,
    root_of_trust: RootOfTrust,
}

fn get_sev_snp_processor() -> u32 {
    let cpuid_result = unsafe { __cpuid(1) };
    cpuid_result.eax
}

fn get_product_name(product: i32) -> String {
    match product {
        SEV_PRODUCT_MILAN => "Milan".to_string(),
        SEV_PRODUCT_GENOA => "Genoa".to_string(),
        _ => "Unknown".to_string(),
    }
}

fn get_uint64_from_tcb(tcb_version: &TcbVersion) -> u64 {
    let microcode = (tcb_version.microcode as u64) << 56;
    let snp = (tcb_version.snp as u64) << 48;
    let tee = (tcb_version.tee as u64) << 8;
    let bootloader: u64 = tcb_version.bootloader as u64;

    microcode | snp | tee | bootloader
}

fn sev_product(eax: u32) -> SevProduct {
    let extended_family = (eax >> EXTENDED_FAMILY_SHIFT) & 0xff;
    let extended_model = (eax >> EXTENDED_MODEL_SHIFT) & 0xf;
    let family = (eax >> FAMILY_SHIFT) & 0xf;

    let mut product_name = SEV_PRODUCT_UNKNOWN;

    if extended_family == SEV_EXTENDED_FAMILY && family == SEV_FAMILY {
        product_name = match extended_model {
            MILAN_EXTENDED_MODEL => SEV_PRODUCT_MILAN,
            GENOA_EXTENDED_MODEL => SEV_PRODUCT_GENOA,
            _ => {
                return SevProduct {
                    name: SEV_PRODUCT_UNKNOWN,
                };
            }
        };
    }

    SevProduct { name: product_name }
}

fn main() {
    let matches = Command::new("Attestation Policy")
        .about(
            "Processes command line options and outputs a JSON file for Attestation verification",
        )
        .arg(
            Arg::new("policy")
                .long("policy")
                .value_name("INT")
                .help("Sets the policy integer")
                .required(true)
                .value_parser(value_parser!(u64)),
        )
        .get_matches();

    let mut firmware: Firmware = Firmware::open().unwrap();
    let status: SnpPlatformStatus = firmware.snp_platform_status().unwrap();

    let policy: u64 = *matches.get_one::<u64>("policy").unwrap();
    let family_id = BASE64_STANDARD.encode(vec![0; 16]);
    let image_id = BASE64_STANDARD.encode(vec![0; 16]);
    let vmpl = 0;
    let minimum_tcb = get_uint64_from_tcb(&status.platform_tcb_version);
    let minimum_launch_tcb = get_uint64_from_tcb(&status.platform_tcb_version);
    let require_author_key = false;
    let measurement = BASE64_STANDARD.encode(vec![0; 48]);
    let host_data = BASE64_STANDARD.encode(vec![0; 32]);
    let report_id_ma = BASE64_STANDARD.encode(vec![0xFF; 32]);
    let cpu_id: Identifier = firmware.get_identifier().unwrap();
    let chip_id: String = BASE64_STANDARD.encode(cpu_id.0);
    let minimum_build = status.build_id;
    let minimum_version = status.version.to_string();
    let permit_provisional_firmware = true;
    let require_id_block = false;
    let product = sev_product(get_sev_snp_processor());

    let policy = SnpPolicy {
        policy,
        family_id,
        image_id,
        vmpl,
        minimum_tcb,
        minimum_launch_tcb,
        require_author_key,
        measurement,
        host_data,
        report_id_ma,
        chip_id,
        minimum_build,
        minimum_version,
        permit_provisional_firmware,
        require_id_block,
        product,
    };

    let root_of_trust = RootOfTrust {
        product: get_product_name(product.name),
        check_crl: true,
        disallow_network: false,
        product_line: get_product_name(product.name),
    };

    let computation = Computation {
        policy,
        root_of_trust,
    };

    let json = serde_json::to_string_pretty(&computation).expect("Failed to serialize to JSON");
    let mut file = File::create(ATTESTATION_POLICY_JSON).expect("Failed to create file");
    file.write_all(json.as_bytes())
        .expect("Failed to write to file");

    println!("Computation JSON has been written to {}", ATTESTATION_POLICY_JSON);
}
