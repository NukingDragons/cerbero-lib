mod vault_trait;
pub use vault_trait::Vault;

mod file;
pub use file::FileVault;

mod buf;
pub use buf::BufVault;

mod empty;
pub use empty::EmptyVault;
