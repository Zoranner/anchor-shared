use std::fs;

use anchor_setup::write_service_config;
use tempfile::tempdir;

const VERIFYING_KEY_HEX: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn writes_validated_service_config_without_leaving_a_temporary_file() {
    let directory = tempdir().unwrap();
    let config = directory.path().join("service.toml");
    let database = directory.path().join("audit.db");

    write_service_config(&config, &database, Some("laptop-1"), VERIFYING_KEY_HEX).unwrap();

    let configured: toml::Value = fs::read_to_string(&config).unwrap().parse().unwrap();
    assert_eq!(
        configured["database"].as_str(),
        Some(database.to_str().unwrap())
    );
    assert_eq!(
        configured["verifying_key_hex"].as_str(),
        Some(VERIFYING_KEY_HEX)
    );
    assert_eq!(configured["device_id"].as_str(), Some("laptop-1"));
    assert!(!directory.path().join("service.toml.tmp").exists());
}

#[test]
fn rejects_invalid_input_without_replacing_existing_config() {
    let directory = tempdir().unwrap();
    let config = directory.path().join("service.toml");
    fs::write(&config, "previous configuration\n").unwrap();

    let error = write_service_config(
        &config,
        &directory.path().join("audit.db"),
        Some("laptop\n1"),
        VERIFYING_KEY_HEX,
    )
    .unwrap_err();

    assert!(error.to_string().contains("device_id"));
    assert_eq!(
        fs::read_to_string(&config).unwrap(),
        "previous configuration\n"
    );
}

#[test]
fn generates_a_local_device_id_when_none_is_provided() {
    let directory = tempdir().unwrap();
    let config = directory.path().join("service.toml");
    let database = directory.path().join("audit.db");

    write_service_config(&config, &database, None, VERIFYING_KEY_HEX).unwrap();

    let configured: toml::Value = fs::read_to_string(&config).unwrap().parse().unwrap();
    let device_id = configured["device_id"].as_str().unwrap();
    assert!(device_id.starts_with("device-"));

    write_service_config(&config, &database, None, VERIFYING_KEY_HEX).unwrap();

    let reconfigured: toml::Value = fs::read_to_string(&config).unwrap().parse().unwrap();
    assert_eq!(reconfigured["device_id"].as_str(), Some(device_id));
}
