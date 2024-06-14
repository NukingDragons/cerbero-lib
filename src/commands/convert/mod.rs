use crate::{
	core::{CredFormat, Vault},
	Result,
};

/// Convert tickets between krb (Windows) and ccache (Linux) formats
///
/// # Examples
///
/// ```
/// use cerbero_lib::{convert, CredFormat, FileVault};
///
/// fn main()
/// {
///     let in_vault = FileVault::new("in.krb".to_string());
///     let out_vault = FileVault::new("out.ccache".to_string());
///
///     match convert(&in_vault, &out_vault, Some(CredFormat::Ccache))
///     {
///         Ok(_) => (),
///         Err(e) => panic!("Failed to convert: {}", e),
///     };
/// }
/// ```
pub fn convert(in_vault: &dyn Vault, out_vault: &dyn Vault, cred_format: Option<CredFormat>) -> Result<()>
{
	let krb_cred = in_vault.dump()?;
	let in_cred_format = in_vault.support_cred_format()?.ok_or("Unknown input file format: Maybe an empty file?")?;

	let cred_format = match cred_format
	{
		Some(cred_format) => cred_format,
		None => match CredFormat::from_file_extension(out_vault.id())
		{
			Some(cred_format) => cred_format,
			None => in_cred_format.contrary(),
		},
	};

	out_vault.save_as(krb_cred, cred_format)?;

	Ok(())
}
