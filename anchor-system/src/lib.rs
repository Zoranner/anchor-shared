//! Anchor Guard 平台适配层：设备、网卡、刻录、密钥保护与服务控制。

pub mod burning;
pub mod error;
pub mod inventory;
pub mod key_protect;
pub mod nic;
pub mod pipe;
pub mod removable;
pub mod session;
pub mod usb;

#[cfg(test)]
mod testutil {
    use serde::{de::DeserializeOwned, Serialize};

    pub fn assert_variant_roundtrip<T>(value: &T, serialized: &str)
    where
        T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        assert_eq!(
            serde_json::to_string(value).unwrap(),
            format!("\"{serialized}\"")
        );
        assert_eq!(
            &serde_json::from_str::<T>(&format!("\"{serialized}\"")).unwrap(),
            value
        );
    }
}
