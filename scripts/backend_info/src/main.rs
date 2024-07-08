use clap::{Arg, Command, value_parser};
use serde::Serialize;
use std::fs::File;
use std::io::Write;
use sysinfo::System;
use regex::Regex;
use sev::firmware::host::*;

const BACKEND_INFO_JSON : &str = "backend_info.json";

#[derive(Serialize)]
struct Vmpl {
    value : u32,
}

#[derive(Serialize)]
struct SnpPolicy {
    policy: u64,
    family_id: Vec<u8>,
    image_id: Vec<u8>,
    vmpl: Vmpl,
    minimum_tcb: u64,
    minimum_launch_tcb: u64,
    require_author_key: bool,
    measurement: Vec<u8>,
    host_data: Vec<u8>,
    report_id_ma: Vec<u8>,
    chip_id: Vec<u8>,
    minimum_build: u32,
    minimum_version: String,
    permit_provisional_firmware: bool,
    require_id_block: bool,
}

#[derive(Serialize)]
struct RootOfTrust {
    product: String,
    check_crl : bool,
    disallow_network : bool,
}

#[derive(Serialize)]
struct Computation {
    snp_policy: SnpPolicy,
    root_of_trust: RootOfTrust,
}

fn get_product_name() -> String {
    let mut sys = System::new_all();
    sys.refresh_all();
    
    let re = Regex::new(r"EPYC.*7..3.*").unwrap();

    for cpu in sys.cpus() {
        if re.is_match(cpu.brand()) {
            return "Milan".to_string()
        }
    }

    "Unknown".to_string()
}

fn get_uint64_from_tcb(tcb_version : &TcbVersion) -> u64 {
    let microcode = (tcb_version.microcode as u64) << 56;
    let snp = (tcb_version.snp as u64) << 48;
    let tee = (tcb_version.tee as u64) << 8;
    let bootloader = tcb_version.bootloader as u64;

    microcode | snp | tee | bootloader
}

fn main() {
    let matches = Command::new("Backend info")
        .about("Processes command line options and outputs a JSON file for Attestation verification")
        .arg(Arg::new("policy")
            .long("policy")
            .value_name("INT")
            .help("Sets the policy integer")
            .required(true)
            .value_parser(value_parser!(u64)))
        .get_matches();

    let mut firmware: Firmware = Firmware::open().unwrap();
    let status: SnpPlatformStatus = firmware.snp_platform_status().unwrap();

    let policy: u64 = *matches.get_one::<u64>("policy").unwrap();
    let family_id = vec![0];
    let image_id = vec![0];
    let vmpl = Vmpl { value: 0};
    let minimum_tcb = get_uint64_from_tcb(&status.platform_tcb_version);
    let minimum_launch_tcb = get_uint64_from_tcb(&status.platform_tcb_version);
    let require_author_key = false;
    let measurement = vec![0];
    let host_data = vec![0];
    let report_id_ma = vec![0];
    let cpu_id: Identifier = firmware.get_identifier().unwrap();
    let chip_id: Vec<u8> = cpu_id.0;
    let minimum_build = status.build_id;
    let minimum_version = status.version.to_string();
    let permit_provisional_firmware = false;
    let require_id_block = false;

    let snp_policy = SnpPolicy {
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
    };

    let root_of_trust = RootOfTrust {
        product : get_product_name(),
        check_crl : true,
        disallow_network : false,
    };

    let computation = Computation {
        snp_policy,
        root_of_trust,
    };

    let json = serde_json::to_string_pretty(&computation).expect("Failed to serialize to JSON");
    let mut file = File::create(BACKEND_INFO_JSON).expect("Failed to create file");
    file.write_all(json.as_bytes()).expect("Failed to write to file");

    println!("Computation JSON has been written to {}", BACKEND_INFO_JSON);
}
