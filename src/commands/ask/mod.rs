mod ask_tgs;
mod ask_tgt;

use ask_tgs::{ask_s4u2proxy, ask_s4u2self, ask_tgs};
use ask_tgt::ask_tgt;

use crate::{
	communication::KdcComm,
	core::{CredFormat, KrbUser, Vault},
	error::Result,
};
use kerberos_crypto::Key;

/// Asks the KDC to craft Kerberos tickets (TGT/TGS) from the KDC (Domain Controller in Active Directory environment)
///
/// If impersonate_user is specified in addition to the service, then the S4U2Self extension will be used
///
/// If impersonate_user is specified and service is not, then the S4U2Proxy extension will be used
///
/// The ticket will be placed inside of the `vault` argument
///
/// # Examples
///
/// ```
/// use cerbero_lib::{ask, CredFormat, FileVault, KdcComm, Kdcs, Key, KrbUser, TransportProtocol, Vault};
/// use std::net::{IpAddr, Ipv4Addr};
///
/// fn main()
/// {
///     let mut kdcs = Kdcs::new();
///     let kdc_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
///     kdcs.insert("DOMAIN.COM".to_string(), kdc_ip);
///
///     let user = KrbUser::new("Username".to_string(), "DOMAIN.COM".to_string());
///     let key = Key::Secret("Password".to_string());
///     let kdccomm = KdcComm::new(kdcs, TransportProtocol::TCP);
///     let mut vault = FileVault::new("tickets.ccache".to_string());
///
///     match ask(user, Some(key), None, None, None, None, &mut vault, CredFormat::Ccache, kdccomm)
///     {
///         Ok(_) =>
///         {
///             for ticket in vault.dump().expect("Failed to dump tickets").iter()
///             {
///                 println!("{:?}", ticket);
///             }
///         },
///         Err(e) => panic!("Failed to ask the KDC for a ticket: {}", e),
///     };
/// }
/// ```
pub fn ask(user: KrbUser,
           user_key: Option<Key>,
           impersonate_user: Option<KrbUser>,
           service: Option<String>,
           user_service: Option<String>,
           rename_service: Option<String>,
           vault: &mut dyn Vault,
           credential_format: CredFormat,
           kdccomm: KdcComm)
           -> Result<()>
{
	match service
	{
		Some(service) => match impersonate_user
		{
			Some(impersonate_user) => ask_s4u2proxy(
			                                        user,
			                                        impersonate_user,
			                                        service,
			                                        user_service,
			                                        rename_service,
			                                        vault,
			                                        user_key.as_ref(),
			                                        credential_format,
			                                        kdccomm,
			),
			None => ask_tgs(user, service, rename_service, user_key.as_ref(), credential_format, vault, kdccomm),
		},
		None => match impersonate_user
		{
			Some(impersonate_user) =>
			{
				ask_s4u2self(user, impersonate_user, user_service, vault, user_key.as_ref(), credential_format, kdccomm)
			},
			None => match user_key
			{
				Some(user_key) => ask_tgt(user, &user_key, credential_format, vault, kdccomm),
				None => Err("Required credentials to request a TGT")?,
			},
		},
	}
}
