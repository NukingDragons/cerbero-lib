use super::Vault;
use crate::communication::{KdcComm, KrbChannel};
use crate::core::request_s4u2self_tgs;
use crate::core::request_tgt;
use crate::core::KrbUser;
use crate::core::TicketCred;
use crate::error::Result;
use kerberos_crypto::Key;

/// Function to get a TGT from the credentials file
/// or request it if it is necessary
pub fn get_user_tgt(user: KrbUser,
                    user_key: Option<&Key>,
                    etype: Option<i32>,
                    vault: &mut dyn Vault,
                    channel: &dyn KrbChannel)
                    -> Result<TicketCred>
{
	let tgt_result = get_user_tgt_from_file(&user, vault, etype);

	if let Ok(tgt) = tgt_result
	{
		return Ok(tgt);
	}

	let user_key = user_key.ok_or("Unable to request TGT without user credentials")?;

	if let Some(etype) = etype
	{
		if !user_key.etypes().contains(&etype)
		{
			Err(format!("Incompatible etype {} with provided key", etype))?
		}
	}

	let tgt = request_tgt(user.clone(), user_key, etype, channel)?;

	vault.add(tgt.clone())?;

	Ok(tgt)
}

/// Try to get the TGT user from the credentials file
fn get_user_tgt_from_file(user: &KrbUser, vault: &dyn Vault, etype: Option<i32>) -> Result<TicketCred>
{
	let mut tgts = vault.get_user_tgts(user)?;

	if tgts.is_empty()
	{
		Err(format!("No TGT found for '{}", user.name))?
	}

	if let Some(etype) = etype
	{
		tgts = tgts.etype(etype);

		if tgts.is_empty()
		{
			Err(format!("No TGT with etype '{}' found for '{}'", etype, user.name))?
		}
	}

	Ok(tgts.get(0).unwrap().clone())
}

/// Function to get a TGS of an impersonated user from file
/// or request it if it is necessary
pub fn get_impersonation_ticket(user: KrbUser,
                                impersonate_user: KrbUser,
                                user_service: Option<String>,
                                tgt: TicketCred,
                                vault: &mut dyn Vault,
                                kdccomm: &mut KdcComm)
                                -> Result<TicketCred>
{
	let tickets = vault.s4u2self_tgss(&user, &impersonate_user, user_service.as_ref())?;

	if !tickets.is_empty()
	{
		let s4u2self_tgs = tickets.get(0).unwrap();

		return Ok(s4u2self_tgs.clone());
	}

	let s4u2self_tgs = request_s4u2self_tgs(user, impersonate_user.clone(), user_service, tgt, kdccomm)?;

	vault.add(s4u2self_tgs.clone())?;

	Ok(s4u2self_tgs)
}
