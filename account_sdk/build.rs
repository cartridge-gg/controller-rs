use cainome::rs::{Abigen, ExecutionVersion};
use sha2::{Digest, Sha256};
use starknet::core::types::Felt;
use std::io::Read;
use std::{collections::HashMap, fs, path::PathBuf, process::Command, time::Instant};

fn main() {
    // Track individual files instead of directories
    for entry in fs::read_dir("./artifacts/classes").unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_file() && path.extension().unwrap_or_default() == "json" {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
    // Track forwarder artifacts in subdirectory
    if let Ok(entries) = fs::read_dir("./artifacts/classes/forwarder") {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && path.extension().unwrap_or_default() == "json" {
                println!("cargo:rerun-if-changed={}", path.display());
            }
        }
    }
    println!("cargo:rerun-if-changed=./artifacts/metadata.json");

    let controller_path = PathBuf::from("src/abigen/controller.rs");
    let erc20_path = PathBuf::from("src/abigen/erc_20.rs");
    let artifacts_path = PathBuf::from("src/artifacts.rs");

    let artifacts_hash = {
        let mut hasher = Sha256::new();
        let mut paths: Vec<_> = fs::read_dir("./artifacts/classes")
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| path.is_file() && path.extension().unwrap_or_default() == "json")
            .collect();

        // Include forwarder artifacts in hash calculation
        if let Ok(entries) = fs::read_dir("./artifacts/classes/forwarder") {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() && path.extension().unwrap_or_default() == "json" {
                    paths.push(path);
                }
            }
        }

        paths.sort(); // Ensure deterministic order

        for path in paths {
            if let Ok(mut file) = fs::File::open(&path) {
                let mut buffer = Vec::new();
                if file.read_to_end(&mut buffer).is_ok() {
                    hasher.update(&buffer);
                }
            }
        }

        if let Ok(mut file) = fs::File::open("./artifacts/metadata.json") {
            let mut buffer = Vec::new();
            if file.read_to_end(&mut buffer).is_ok() {
                hasher.update(&buffer);
            }
        }

        format!("{:x}", hasher.finalize())
    };

    let hash_file = PathBuf::from("./target/.artifacts_hash");
    let stored_hash = fs::read_to_string(&hash_file).ok();

    let artifacts_changed = match stored_hash.clone() {
        Some(hash) => artifacts_hash != hash,
        None => {
            println!("No cached hash found, will generate all files");
            true
        }
    };

    let need_controller = !controller_path.exists() || artifacts_changed;
    let need_erc20 = !erc20_path.exists() || artifacts_changed;
    let need_artifacts = !artifacts_path.exists() || artifacts_changed;

    if artifacts_changed && stored_hash.is_some() {
        println!("Artifacts have changed, regenerating files");
    }

    if need_controller {
        let now = Instant::now();
        generate_controller_bindings();
        println!("Controller bindings generated in {:?}", now.elapsed());
    }

    if need_erc20 {
        let now = Instant::now();
        generate_erc20_bindings();
        println!("ERC20 bindings generated in {:?}", now.elapsed());
    }

    if need_artifacts {
        let now = Instant::now();
        generate_artifacts();
        println!("Artifacts generated in {:?}", now.elapsed());
    }

    // Only format if we generated something
    if need_controller || need_erc20 || need_artifacts {
        println!("Formatting generated files...");
        Command::new("cargo")
            .args([
                "fmt",
                "--",
                "src/abigen/controller.rs",
                "src/abigen/erc_20.rs",
                "src/artifacts.rs",
            ])
            .status()
            .expect("Failed to format the code");

        // Save the artifacts hash for next time
        fs::create_dir_all("./target").ok();
        fs::write(&hash_file, &artifacts_hash).unwrap();
        println!("Saved artifacts hash: {}", &artifacts_hash[..8]); // Show first 8 chars
    } else {
        println!("All files up to date, skipping generation and formatting");
    }
}

fn generate_artifacts() {
    let mut controllers = String::new();
    let mut versions = Vec::new();

    for entry in fs::read_dir("./artifacts/classes").unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_file() && path.extension().unwrap_or_default() == "json" {
            let filename = path.file_name().unwrap().to_str().unwrap();
            if filename.starts_with("controller.") && filename.ends_with(".contract_class.json") {
                let version = filename
                    .strip_prefix("controller.")
                    .unwrap()
                    .strip_suffix(".contract_class.json")
                    .unwrap();
                versions.push(version.to_string());

                controllers.push_str(&format!(
                    r#"m.insert(Version::{}, ContractClass {{
            content: include_str!(".{}"),
            hash: felt!("{:#x}"),
            casm_hash: felt!("{:#x}"),
        }});"#,
                    version.replace('.', "_").to_uppercase(),
                    // Replace the '\' with '/' on Windows, meaning the path is always the same
                    // on all platforms. Windows also accepts '/' as a path separator.
                    path.display().to_string().replace("\\", "/"),
                    extract_class_hash(&path),
                    extract_compiled_class_hash(version)
                ));
            }
        }
    }

    // Generate forwarder artifact if available
    let forwarder_code = generate_forwarder_artifact();

    // Sort to ensure output is deterministic
    versions.sort_by(|a, b| {
        if a == "latest" {
            std::cmp::Ordering::Greater
        } else if b == "latest" {
            std::cmp::Ordering::Less
        } else {
            let a_parts: Vec<&str> = a.trim_start_matches('v').split('.').collect();
            let b_parts: Vec<&str> = b.trim_start_matches('v').split('.').collect();
            for (a_part, b_part) in a_parts.iter().zip(b_parts.iter()) {
                let a_num: u32 = a_part.parse().unwrap();
                let b_num: u32 = b_part.parse().unwrap();
                match a_num.cmp(&b_num) {
                    std::cmp::Ordering::Equal => continue,
                    other => return other,
                }
            }
            a_parts.len().cmp(&b_parts.len())
        }
    });

    let latest_version = versions.iter().max().unwrap();
    let artifacts = format!(
        r#"// This file is auto-generated. Do not modify manually.
use lazy_static::lazy_static;
use std::collections::HashMap;
use starknet_types_core::felt::Felt;
use starknet::macros::felt;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum Version {{
    {enum_variants}
}}

#[derive(Clone, Copy, Debug)]
pub struct ContractClass {{
    pub content: &'static str,
    pub hash: Felt,
    pub casm_hash: Felt,
}}

unsafe impl Sync for ContractClass {{}}

/// Forwarder contract class with both sierra and casm content
#[derive(Clone, Copy, Debug)]
pub struct ForwarderClass {{
    pub content: &'static str,
    pub casm_content: &'static str,
    pub class_hash: Felt,
}}

unsafe impl Sync for ForwarderClass {{}}

{forwarder_code}

lazy_static! {{
    pub static ref CONTROLLERS: HashMap<Version, ContractClass> = {{
        let mut m = HashMap::new();
        {controllers}
        m
    }};

    pub static ref DEFAULT_CONTROLLER: &'static ContractClass = CONTROLLERS.get(&Version::{default_version}).unwrap();

    pub static ref VERSIONS: Vec<Version> = vec![
        {versions}
    ];
}}
"#,
        forwarder_code = forwarder_code,
        enum_variants = versions
            .iter()
            .map(|v| v.replace('.', "_").to_uppercase().to_string())
            .collect::<Vec<_>>()
            .join(", "),
        controllers = controllers,
        default_version = latest_version.replace('.', "_").to_uppercase(),
        versions = versions
            .iter()
            .map(|v| format!("Version::{}", v.replace('.', "_").to_uppercase()))
            .collect::<Vec<_>>()
            .join(", ")
    );

    fs::write("./src/artifacts.rs", artifacts).unwrap();

    // Write artifacts to JSON file with deterministic metadata
    let json_artifacts = serde_json::json!({
        "versions": versions,
        "latest_version": latest_version,
        "controllers": versions.iter().map(|v| {
            (v.to_string(), {
                let path = format!("./artifacts/classes/controller.{v}.contract_class.json");
                let class_hash = extract_class_hash(&PathBuf::from(&path));
                let casm_hash = extract_compiled_class_hash(v);
                let mut controller_info = serde_json::json!({
                    "class_hash": format!("{:#x}", class_hash),
                    "casm_hash": format!("{:#x}", casm_hash)
                });

                // Add deterministic version metadata for non-latest versions
                if v != "latest" {
                    let outside_execution_version = determine_outside_execution_version(v);
                    let changes = determine_version_changes(v);

                    controller_info["outside_execution_version"] = serde_json::Value::String(outside_execution_version);
                    controller_info["changes"] = serde_json::Value::Array(changes.into_iter().map(serde_json::Value::String).collect());
                }

                controller_info
            })
        }).collect::<HashMap<_,_>>()
    });

    fs::write(
        "./artifacts/metadata.json",
        serde_json::to_string_pretty(&json_artifacts).unwrap(),
    )
    .unwrap();
}

fn determine_outside_execution_version(version: &str) -> String {
    match version {
        "v1.0.4" | "v1.0.5" => "V2".to_string(),
        _ => "V3".to_string(), // v1.0.6 and later use V3
    }
}

fn determine_version_changes(version: &str) -> Vec<String> {
    match version {
        "v1.0.4" => vec![],
        "v1.0.5" => vec!["Improved session token implementation".to_string()],
        "v1.0.6" => vec![
            "Support session key message signing".to_string(),
            "Support session guardians".to_string(),
            "Improve paymaster nonce management".to_string(),
        ],
        "v1.0.7" => vec!["Unified message signature verification".to_string()],
        "v1.0.8" => vec!["Improved session message signature".to_string()],
        "v1.0.9" => vec!["Wildcard session support".to_string()],
        _ => vec![], // Unknown versions or latest
    }
}

fn extract_compiled_class_hash(version: &str) -> Felt {
    use starknet::core::types::contract::CompiledClass;
    use std::fs::File;
    use std::io::BufReader;
    let compiled_class: CompiledClass = serde_json::from_reader(BufReader::new(
        File::open(format!(
            "./artifacts/classes/controller.{version}.compiled_contract_class.json"
        ))
        .unwrap(),
    ))
    .unwrap();
    compiled_class.class_hash().unwrap()
}

fn extract_class_hash(path: &PathBuf) -> Felt {
    use starknet::core::types::contract::SierraClass;
    use std::fs::File;
    use std::io::BufReader;
    let compiled_class: SierraClass =
        serde_json::from_reader(BufReader::new(File::open(path).unwrap())).unwrap();
    compiled_class.class_hash().unwrap()
}

fn generate_controller_bindings() {
    let abigen = Abigen::new(
        "Controller",
        "./artifacts/classes/controller.latest.contract_class.json",
    )
    .with_execution_version(ExecutionVersion::V3)
    .with_types_aliases(HashMap::from([
        (
            String::from(
                "argent::outside_execution::outside_execution::outside_execution_component::Event",
            ),
            String::from("OutsideExecutionV3Event"),
        ),
        (
            String::from("argent::outside_execution::interface::OutsideExecution"),
            String::from("OutsideExecutionV3"),
        ),
        (
            String::from("controller::account::CartridgeAccount::Event"),
            String::from("ControllerEvent"),
        ),
        (
            String::from(
                "controller::external_owners::external_owners::external_owners_component::Event",
            ),
            String::from("ExternalOwnersEvent"),
        ),
        (
            String::from(
                "controller::delegate_account::delegate_account::delegate_account_component::Event",
            ),
            String::from("DelegateAccountEvent"),
        ),
        (
            String::from("controller::session::session::session_component::Event"),
            String::from("SessionEvent"),
        ),
        (
            String::from(
                "controller::multiple_owners::multiple_owners::multiple_owners_component::Event",
            ),
            String::from("MultipleOwnersEvent"),
        ),
        (
            String::from("controller::introspection::src5::src5_component::Event"),
            String::from("Src5ComponentEvent"),
        ),
        (
            String::from("openzeppelin::token::erc20::erc20::ERC20Component::Event"),
            String::from("ERC20ComponentEvent"),
        ),
        (
            String::from("openzeppelin::access::ownable::ownable::OwnableComponent::Event"),
            String::from("OwnableComponentEvent"),
        ),
        (
            String::from("openzeppelin_upgrades::upgradeable::UpgradeableComponent::Event"),
            String::from("UpgradeEvent"),
        ),
        (
            String::from("openzeppelin_security::reentrancyguard::ReentrancyGuardComponent::Event"),
            String::from("ReentrancyGuardEvent"),
        ),
    ]))
    .with_derives(vec![
        String::from("Clone"),
        String::from("serde::Serialize"),
        String::from("serde::Deserialize"),
        String::from("PartialEq"),
        String::from("Debug"),
    ])
    .with_contract_derives(vec![String::from("Clone"), String::from("Debug")]);

    abigen
        .generate()
        .expect("Fail to generate bindings for Controller")
        .write_to_file("./src/abigen/controller.rs")
        .unwrap();
}

fn generate_erc20_bindings() {
    let abigen = Abigen::new("Erc20", "./artifacts/classes/erc20.contract_class.json")
        .with_execution_version(ExecutionVersion::V3)
        .with_types_aliases(HashMap::from([
            (
                String::from("openzeppelin::token::erc20::erc20::ERC20Component::Event"),
                String::from("ERC20ComponentEvent"),
            ),
            (
                String::from("openzeppelin::access::ownable::ownable::OwnableComponent::Event"),
                String::from("OwnableComponentEvent"),
            ),
            (
                String::from("openzeppelin::upgrades::upgradeable::UpgradeableComponent::Event"),
                String::from("UpgradeEvent"),
            ),
            (
                String::from(
                    "openzeppelin::security::reentrancyguard::ReentrancyGuardComponent::Event",
                ),
                String::from("ReentrancyGuardEvent"),
            ),
        ]))
        .with_derives(vec![
            String::from("Clone"),
            String::from("serde::Serialize"),
            String::from("serde::Deserialize"),
            String::from("PartialEq"),
            String::from("Debug"),
        ])
        .with_contract_derives(vec![String::from("Debug")]);

    abigen
        .generate()
        .expect("Fail to generate bindings for ERC20")
        .write_to_file("./src/abigen/erc_20.rs")
        .unwrap();
}

fn generate_forwarder_artifact() -> String {
    let forwarder_sierra_path =
        PathBuf::from("./artifacts/classes/forwarder/avnu_Forwarder.contract_class.json");
    let forwarder_casm_path =
        PathBuf::from("./artifacts/classes/forwarder/avnu_Forwarder.compiled_contract_class.json");

    if !forwarder_sierra_path.exists() || !forwarder_casm_path.exists() {
        // Forwarder artifacts not available, return empty code
        return String::new();
    }

    let class_hash = extract_class_hash(&forwarder_sierra_path);

    format!(
        r#"/// AVNU Forwarder contract for paymaster integration
pub const FORWARDER: ForwarderClass = ForwarderClass {{
    content: include_str!("../artifacts/classes/forwarder/avnu_Forwarder.contract_class.json"),
    casm_content: include_str!("../artifacts/classes/forwarder/avnu_Forwarder.compiled_contract_class.json"),
    class_hash: felt!("{class_hash:#x}"),
}};"#
    )
}
