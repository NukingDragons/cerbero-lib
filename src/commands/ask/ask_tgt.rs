use crate::{
	communication::KdcComm,
	core::{request_tgt, CredFormat, KrbUser, Vault},
	error::Result,
};
use kerberos_crypto::Key;

/// Main function to ask a TGT
pub fn ask_tgt(user: KrbUser,
               user_key: &Key,
               cred_format: CredFormat,
               vault: &mut dyn Vault,
               mut kdccomm: KdcComm)
               -> Result<()>
{
	let channel = kdccomm.create_channel(&user.realm)?;

	let tgt = request_tgt(user.clone(), user_key, None, &*channel)?;

	vault.add(tgt)?;
	vault.change_format(cred_format)?;

	Ok(())
}
