# anchor-shared

`anchor-shared` 存放 Anchor Guard 客户端和服务端共享的 crate，以及跨仓项目文档。

## Crate

- `anchor-core`：策略模型、签名验签、版本和有效期判断、审计事件与 hash chain。
- `anchor-protocol`：服务端和客户端共享的 DTO、错误码和协议版本。

## 使用方

`anchor-client` 和 `anchor-server` 通过各自的 `crates/shared` Git submodule 引用本仓：

```toml
anchor-core = { path = "crates/shared/core" }
anchor-protocol = { path = "crates/shared/protocol" }
```

修改共享协议或 core 行为时，先在本仓提交并打版本标签，再更新两个父仓的 submodule 指针。

## 验证

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
```
