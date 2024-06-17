use cerbero_lib::{ask, CredFormat, FileVault, KdcComm, Kdcs, Key, TransportProtocol, Vault};
use std::net::{IpAddr, Ipv4Addr};

fn main()
{
	let mut kdcs = Kdcs::new();
	let kdc_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
	kdcs.insert("DOMAIN.COM".to_string(), kdc_ip);

	let key = Key::Secret("Password".to_string());
	let kdccomm = KdcComm::new(kdcs, TransportProtocol::TCP);
	let mut vault = FileVault::new("tickets.ccache".to_string());

	match ask("DOMAIN.COM", "Username", Some(key), None, None, None, None, &mut vault, CredFormat::Ccache, kdccomm)
	{
		Ok(_) =>
		{
			for ticket in vault.dump().expect("Failed to dump tickets").iter()
			{
				println!("{:?}", ticket);
			}
		},
		Err(e) => panic!("Failed to ask the KDC for a ticket: {}", e),
	};
}
