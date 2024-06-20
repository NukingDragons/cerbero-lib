mod vault_trait;
pub use vault_trait::Vault;

mod file;
pub use file::FileVault;

mod buf;
pub use buf::BufVault;

#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "windows")]
pub use windows::WindowsVault;

mod empty;
pub use empty::EmptyVault;
