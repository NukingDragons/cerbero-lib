use super::Vault;
use crate::core::CredFormat;
use crate::core::{KrbUser, TicketCred, TicketCreds};
use crate::error::Result;

/// Reference for implementing the `Vault` trait
pub struct EmptyVault
{
	ticket_creds: TicketCreds,
}

impl EmptyVault
{
	pub fn new() -> Self
	{
		return Self { ticket_creds: TicketCreds::empty() };
	}
}

impl Vault for EmptyVault
{
	fn id(&self) -> &str
	{
		return "Nowhere";
	}

	fn support_cred_format(&self) -> Result<Option<CredFormat>>
	{
		Ok(None)
	}

	fn add(&mut self, ticket_info: TicketCred) -> Result<()>
	{
		self.ticket_creds.push(ticket_info);
		Ok(())
	}

	fn dump(&self) -> Result<TicketCreds>
	{
		Ok(self.ticket_creds.clone())
	}

	fn save(&self, _: TicketCreds) -> Result<()>
	{
		Ok(())
	}

	fn save_as(&self, _: TicketCreds, _: CredFormat) -> Result<()>
	{
		Ok(())
	}

	fn change_format(&self, _: CredFormat) -> Result<()>
	{
		Ok(())
	}

	fn get_user_tgts(&self, user: &KrbUser) -> Result<TicketCreds>
	{
		Ok(self.ticket_creds.user_tgt_realm(user, &user.realm))
	}

	fn s4u2self_tgss(&self,
	                 user: &KrbUser,
	                 impersonate_user: &KrbUser,
	                 user_service: Option<&String>)
	                 -> Result<TicketCreds>
	{
		Ok(self.ticket_creds.s4u2self_tgss(user, impersonate_user, user_service))
	}
}
