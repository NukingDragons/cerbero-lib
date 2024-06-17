use super::Vault;
use crate::{
	core::{CredFormat, TicketCred, TicketCreds},
	error::Error,
	KrbUser, Result,
};
use kerberos_asn1::{Asn1Object, KrbCred};
use kerberos_ccache::CCache;
use std::cell::RefCell;

/// Vault that exists entirely in memory, for when you can't or don't want to touch disk
pub struct BufVault
{
	ticket_creds: RefCell<TicketCreds>,
}

impl BufVault
{
	pub fn new() -> Self
	{
		Self { ticket_creds: RefCell::new(TicketCreds::empty()) }
	}
}

impl Default for BufVault
{
	fn default() -> Self
	{
		Self::new()
	}
}

impl Vault for BufVault
{
	fn id(&self) -> &str
	{
		"Memory"
	}

	fn support_cred_format(&self) -> Result<Option<CredFormat>>
	{
		Ok(Some(determine_ticket_format(self.ticket_creds.borrow().clone())?))
	}

	fn add(&mut self, ticket_info: TicketCred) -> Result<()>
	{
		self.ticket_creds.borrow_mut().push(ticket_info);
		Ok(())
	}

	fn dump(&self) -> Result<TicketCreds>
	{
		Ok(self.ticket_creds.borrow().clone())
	}

	fn save(&self, tickets: TicketCreds) -> Result<()>
	{
		*self.ticket_creds.borrow_mut() = tickets;
		Ok(())
	}

	fn save_as(&self, tickets: TicketCreds, cred_format: CredFormat) -> Result<()>
	{
		self.save(rebuild_ticket(tickets, cred_format)?)
	}

	fn change_format(&self, cred_format: CredFormat) -> Result<()>
	{
		self.save_as(self.ticket_creds.borrow().clone(), cred_format)
	}

	fn get_user_tgts(&self, user: &KrbUser) -> Result<TicketCreds>
	{
		Ok(self.ticket_creds.borrow().user_tgt_realm(user, &user.realm))
	}

	fn s4u2self_tgss(&self,
	                 user: &KrbUser,
	                 impersonate_user: &KrbUser,
	                 user_service: Option<&String>)
	                 -> Result<TicketCreds>
	{
		Ok(self.ticket_creds.borrow().s4u2self_tgss(user, impersonate_user, user_service))
	}
}

fn rebuild_ticket(ticket: TicketCreds, cred_format: CredFormat) -> Result<TicketCreds>
{
	let krb_cred: KrbCred = ticket.into();

	let data = match cred_format
	{
		CredFormat::Krb => krb_cred.build(),
		CredFormat::Ccache =>
		{
			let ccache: CCache =
				krb_cred.try_into().map_err(|_| Error::DataError("Error converting KrbCred to CCache".to_string()))?;
			ccache.build()
		},
	};

	match CCache::parse(&data)
	{
		Ok((_, ccache)) =>
		{
			let krb_cred: KrbCred =
				ccache.try_into().map_err(|_| Error::DataError("Error parsing ccache data content".to_string()))?;

			Ok(TicketCreds::try_from(krb_cred)?)
		},
		Err(_) =>
		{
			let (_, krb_cred) =
				KrbCred::parse(&data).map_err(|_| Error::DataError("Error parsing content of ccache/krb".to_string()))?;

			Ok(TicketCreds::try_from(krb_cred)?)
		},
	}
}

fn determine_ticket_format(ticket: TicketCreds) -> Result<CredFormat>
{
	let data = ticket.as_bytes();

	match CCache::parse(&data)
	{
		Ok((_, ccache)) =>
		{
			let _: KrbCred =
				ccache.try_into().map_err(|_| Error::DataError("Error parsing ccache data content".to_string()))?;

			Ok(CredFormat::Ccache)
		},
		Err(_) =>
		{
			let (_, _) =
				KrbCred::parse(&data).map_err(|_| Error::DataError("Error parsing content of ccache/krb".to_string()))?;
			Ok(CredFormat::Krb)
		},
	}
}
