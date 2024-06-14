use cerbero_lib::{convert, CredFormat, FileVault};

fn main()
{
	let in_vault = FileVault::new("in.krb".to_string());
	let out_vault = FileVault::new("out.ccache".to_string());

	match convert(&in_vault, &out_vault, Some(CredFormat::Ccache))
	{
		Ok(_) => (),
		Err(e) => panic!("Failed to convert: {}", e),
	};
}
