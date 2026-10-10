use std::fs;
use std::process::Command;

use anchor_core::{crypto, PolicyPackage};
use tempfile::tempdir;

fn valid_config() -> &'static str {
    r#"
version = 1
expires_at = "2026-09-28T00:00:00Z"

[usb]
read = "allow"
write = "deny"

[[usb.allowed]]
instance_id = "USBSTOR\\Disk&Ven_Example&Prod_Storage\\1"

[network]
policy = "deny"

[burning]
policy = "deny"

[scan]
controlled_dirs = ["D:\\workspace"]

[[scan.rules]]
rule_id = "keyword-1"
kind = "keyword"
pattern = "internal"
"#
}

fn keygen(binary: &str, out: &std::path::Path) {
    let status = Command::new(binary)
        .args(["keygen", "--out"])
        .arg(out)
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn keygen_and_sign_produce_a_policy_package_verified_by_the_generated_public_key() {
    let temp = tempdir().unwrap();
    let keys_dir = temp.path().join("keys");
    let config_path = temp.path().join("policy.toml");
    let policy_path = temp.path().join("anchor-guard.policy");
    let binary = env!("CARGO_BIN_EXE_anchor-policy");

    keygen(binary, &keys_dir);
    fs::write(&config_path, valid_config()).unwrap();

    let sign = Command::new(binary)
        .args(["sign", "--key"])
        .arg(keys_dir.join("signing-key.hex"))
        .args(["--config"])
        .arg(&config_path)
        .args(["--out"])
        .arg(&policy_path)
        .status()
        .unwrap();
    assert!(sign.success());

    let package: PolicyPackage = serde_json::from_slice(&fs::read(&policy_path).unwrap()).unwrap();
    let public_key = crypto::verifying_key_from_hex(
        fs::read_to_string(keys_dir.join("verifying-key.hex"))
            .unwrap()
            .trim(),
    )
    .unwrap();
    assert_eq!(package.payload.version, 1);
    assert!(package.verify_signature(&public_key));
}

#[test]
fn keygen_refuses_to_replace_an_existing_key_file() {
    let temp = tempdir().unwrap();
    let keys_dir = temp.path().join("keys");
    fs::create_dir(&keys_dir).unwrap();
    let signing_key = keys_dir.join("signing-key.hex");
    fs::write(&signing_key, "existing-key").unwrap();

    let status = Command::new(env!("CARGO_BIN_EXE_anchor-policy"))
        .args(["keygen", "--out"])
        .arg(&keys_dir)
        .status()
        .unwrap();

    assert!(!status.success());
    assert_eq!(fs::read_to_string(signing_key).unwrap(), "existing-key");
}

#[test]
fn sign_rejects_invalid_policy_configuration() {
    let temp = tempdir().unwrap();
    let binary = env!("CARGO_BIN_EXE_anchor-policy");
    let keys_dir = temp.path().join("keys");
    keygen(binary, &keys_dir);

    for (name, config) in [
        (
            "unknown-field",
            format!("unknown_key = 1\n{}", valid_config()),
        ),
        (
            "blank-file-type",
            valid_config().replace(
                "controlled_dirs = [\"D:\\\\workspace\"]",
                "controlled_dirs = [\"D:\\\\workspace\"]\nfile_types = [\".\"]",
            ),
        ),
        (
            "invalid-expiry",
            valid_config().replace("2026-09-28T00:00:00Z", "not-a-timestamp"),
        ),
        (
            "network-allow-without-object",
            valid_config()
                .replace("read = \"allow\"", "read = \"deny\"")
                .replace("policy = \"deny\"", "policy = \"allow\""),
        ),
        (
            "usb-allow-without-match-field",
            format!("{}\n[[usb.allowed]]\n", valid_config()),
        ),
        (
            "network-allow-with-empty-adapter-id",
            valid_config().replacen("policy = \"deny\"", "policy = \"allow\"", 1)
                + "\n[[network.allowed]]\nadapter_id = \"   \"\n",
        ),
        (
            "burning-allow-with-empty-drive-id",
            valid_config().replace(
                "[burning]\npolicy = \"deny\"",
                "[burning]\npolicy = \"allow\"\n\n[[burning.allowed]]\ndrive_id = \"   \"",
            ),
        ),
    ] {
        let config_path = temp.path().join(format!("{name}.toml"));
        let policy_path = temp.path().join(format!("{name}.json"));
        fs::write(&config_path, config).unwrap();

        let status = Command::new(binary)
            .args(["sign", "--key"])
            .arg(keys_dir.join("signing-key.hex"))
            .args(["--config"])
            .arg(&config_path)
            .args(["--out"])
            .arg(&policy_path)
            .status()
            .unwrap();

        assert!(!status.success(), "{name} must be rejected");
        assert!(!policy_path.exists(), "{name} must not write a package");
    }
}

#[test]
fn documented_policy_example_can_be_signed() {
    let temp = tempdir().unwrap();
    let binary = env!("CARGO_BIN_EXE_anchor-policy");
    let keys_dir = temp.path().join("keys");
    let policy_path = temp.path().join("anchor-guard.policy");
    let example_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("policy-example.toml");
    keygen(binary, &keys_dir);

    let status = Command::new(binary)
        .args(["sign", "--key"])
        .arg(keys_dir.join("signing-key.hex"))
        .args(["--config"])
        .arg(example_path)
        .args(["--out"])
        .arg(&policy_path)
        .status()
        .unwrap();

    assert!(status.success());
    assert!(policy_path.is_file());
}

#[test]
fn default_deny_policy_needs_no_device_identifiers() {
    let temp = tempdir().unwrap();
    let binary = env!("CARGO_BIN_EXE_anchor-policy");
    let keys_dir = temp.path().join("keys");
    let config_path = temp.path().join("deny-all.toml");
    let policy_path = temp.path().join("anchor-guard.policy");
    keygen(binary, &keys_dir);
    fs::write(
        &config_path,
        r#"
version = 1
expires_at = "2026-09-28T00:00:00Z"

[usb]
read = "deny"
write = "deny"

[network]
policy = "deny"

[burning]
policy = "deny"

[scan]
controlled_dirs = []
"#,
    )
    .unwrap();

    let status = Command::new(binary)
        .args(["sign", "--key"])
        .arg(keys_dir.join("signing-key.hex"))
        .args(["--config"])
        .arg(&config_path)
        .args(["--out"])
        .arg(&policy_path)
        .status()
        .unwrap();

    assert!(status.success());
    let package: PolicyPackage = serde_json::from_slice(&fs::read(&policy_path).unwrap()).unwrap();
    assert!(package.payload.usb.allowed.is_empty());
    assert!(package.payload.network.allowed.is_empty());
    assert!(package.payload.burning.allowed.is_empty());
    assert!(package.payload.scan.controlled_dirs.is_empty());
}
