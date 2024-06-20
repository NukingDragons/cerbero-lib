//! Structs to allow handle easier tickets and their associated KrbCredInfo

use crate::{
	core::{
		forge::{new_nt_enterprise, new_nt_principal, new_nt_srv_inst},
		KrbUser,
	},
	error::{Error, Result},
	CredFormat,
};
use kerberos_asn1::{Asn1Object, EncKrbCredPart, EncryptedData, KrbCred, KrbCredInfo, PrincipalName, Ticket};
use kerberos_ccache::CCache;
use kerberos_constants::etypes::NO_ENCRYPTION;
use std::slice::Iter;

/// Struct to store a vector of `TicketCred` with additional functionality
#[derive(Clone, Debug)]
pub struct TicketCreds
{
	pub ticket_creds: Vec<TicketCred>,
}

impl TicketCreds
{
	pub fn new(ticket_creds: Vec<TicketCred>) -> Self
	{
		Self { ticket_creds }
	}

	pub fn empty() -> Self
	{
		Self { ticket_creds: Vec::new() }
	}

	pub fn push(&mut self, ticket_info: TicketCred)
	{
		self.ticket_creds.push(ticket_info);
	}

	pub fn iter(&self) -> Iter<TicketCred>
	{
		self.ticket_creds.iter()
	}

	pub fn is_empty(&self) -> bool
	{
		self.ticket_creds.is_empty()
	}

	pub fn get(&self, index: usize) -> Option<&TicketCred>
	{
		self.ticket_creds.get(index)
	}

	pub fn filter<P>(&self, predicate: P) -> Self
		where P: Fn(&TicketCred) -> bool
	{
		self.iter().filter(|tci| predicate(tci)).cloned().collect::<Vec<TicketCred>>().into()
	}

	/// Filter tickets for etype
	pub fn etype(&self, etype: i32) -> Self
	{
		self.filter(|tci| tci.cred_info.key.keytype == etype)
	}

	/// Filter tickets for prealm (realm of the client). Case insensitive.
	pub fn prealm(&self, realm: &str) -> Self
	{
		self.filter(|tci| {
			    if let Some(prealm) = &tci.cred_info.prealm
			    {
				    return prealm.to_lowercase() == realm.to_lowercase();
			    }
			    false
		    })
	}

	/// Filter tickets for pname (the name of the client). Case insensitive.
	pub fn pname(&self, name: &PrincipalName) -> Self
	{
		self.filter(|tci| {
			    if let Some(pname) = &tci.cred_info.pname
			    {
				    return pname == name;
			    }
			    false
		    })
	}

	/// Filter tickets for srealm (realm of the service). Case insensitive.
	pub fn srealm(&self, realm: &str) -> Self
	{
		self.filter(|tci| {
			    if let Some(srealm) = &tci.cred_info.srealm
			    {
				    return srealm.to_lowercase() == realm.to_lowercase();
			    }
			    false
		    })
	}

	/// Filter tickets for sname (the name of the service). Case insensitive.
	pub fn sname(&self, name: &PrincipalName) -> Self
	{
		self.filter(|tci| {
			    if let Some(sname) = &tci.cred_info.sname
			    {
				    return sname == name;
			    }
			    false
		    })
	}

	/// Filter tickets for user_realm. Same as prealm. Case insensitive.
	pub fn user_realm(&self, realm: &str) -> Self
	{
		self.prealm(realm)
	}

	/// Filter for the username.
	pub fn username(&self, name: &str) -> Self
	{
		let pname = new_nt_principal(name);
		self.pname(&pname)
	}

	/// Filter for the username and the user realm.
	pub fn user(&self, user: &KrbUser) -> Self
	{
		self.user_realm(&user.realm).username(&user.name)
	}

	/// Filter to only return tickets that includes a given name in service. It
	/// could be the name of the service (e.g: http, cifs), the hostname or any
	/// other string that appears in the service name. Case insensitive.
	pub fn service_name(&self, name: &str) -> Self
	{
		let name_lower = name.to_lowercase();
		self.filter(|tci| {
			    if let Some(sname) = &tci.cred_info.sname
			    {
				    return sname.name_string.iter().map(|s| s.to_lowercase()).any(|s| s.to_lowercase() == name_lower);
			    }
			    false
		    })
	}

	/// Filter to only returns TGTs.
	pub fn tgt(&self) -> Self
	{
		self.service_name("krbtgt")
	}

	/// Filter to only returns TGTs for a given realm.
	pub fn tgt_realm(&self, realm: &str) -> Self
	{
		let tgt_service = new_nt_srv_inst(&format!("krbtgt/{}", realm));
		self.sname(&tgt_service)
	}

	/// Filter to only returns TGTs for a given realm.
	pub fn user_tgt_realm(&self, user: &KrbUser, realm: &str) -> Self
	{
		self.tgt_realm(realm).user(user)
	}

	/// Filter to return tickets for an user to an specific service
	pub fn user_service(&self, client: &KrbUser, sname: &PrincipalName, srealm: &str) -> Self
	{
		self.user(client).sname(sname).srealm(srealm)
	}

	/// Returns the s4u2self tgss.
	pub fn s4u2self_tgss(&self, user: &KrbUser, impersonate_user: &KrbUser, user_service: Option<&String>) -> Self
	{
		let srealm = &user.realm;

		let sname = match user_service
		{
			Some(user_service) => new_nt_srv_inst(user_service),
			None => new_nt_enterprise(user),
		};

		self.user_service(impersonate_user, &sname, srealm)
	}
}

impl From<TicketCreds> for KrbCred
{
	fn from(ticket_creds: TicketCreds) -> KrbCred
	{
		let mut krb_cred = KrbCred::default();
		let mut tickets = Vec::with_capacity(ticket_creds.ticket_creds.len());
		let mut cred_infos = Vec::with_capacity(ticket_creds.ticket_creds.len());

		for ticket_cred_info in ticket_creds.ticket_creds
		{
			tickets.push(ticket_cred_info.ticket);
			cred_infos.push(ticket_cred_info.cred_info);
		}

		krb_cred.tickets = tickets;
		let cred_part = EncKrbCredPart { ticket_info: cred_infos, ..Default::default() };
		krb_cred.enc_part = EncryptedData::new(NO_ENCRYPTION, None, cred_part.build());
		krb_cred
	}
}

/// Convert from Kerberos credentials in plain text, the usual way of storing
/// them in machines. In case the credentials are encrypted this will fail.
impl TryFrom<KrbCred> for TicketCreds
{
	type Error = Error;

	fn try_from(krb_cred: KrbCred) -> Result<Self>
	{
		if krb_cred.enc_part.etype != NO_ENCRYPTION
		{
			return Err(Error::DataError("Unable to decrypt the credentials".to_string()));
		}

		let (_, cred_part) = EncKrbCredPart::parse(&krb_cred.enc_part.cipher).map_err(|_| {
			                                                                     Error::DataError(
				"Error parsing credentials: EncKrbCredPart".to_string()
			)
		                                                                     })?;

		let tickets = krb_cred.tickets;
		let cred_infos = cred_part.ticket_info;

		Ok((tickets, cred_infos).into())
	}
}

impl From<(Vec<Ticket>, Vec<KrbCredInfo>)> for TicketCreds
{
	fn from((tickets, cred_infos): (Vec<Ticket>, Vec<KrbCredInfo>)) -> Self
	{
		let mut ticket_cred_infos = Vec::with_capacity(tickets.len());

		for (ticket, cred_info) in tickets.into_iter().zip(cred_infos.into_iter())
		{
			ticket_cred_infos.push(TicketCred::new(ticket, cred_info));
		}

		Self::new(ticket_cred_infos)
	}
}

impl From<Vec<TicketCred>> for TicketCreds
{
	fn from(v: Vec<TicketCred>) -> Self
	{
		Self::new(v)
	}
}

impl From<TicketCred> for TicketCreds
{
	fn from(ticket_info: TicketCred) -> Self
	{
		Self::new(vec![ticket_info])
	}
}

/// Struct to store a ticket and the related user info, like the session key.
#[derive(Debug, Clone)]
pub struct TicketCred
{
	pub ticket: Ticket,
	pub cred_info: KrbCredInfo,
}

impl TicketCred
{
	pub fn new(ticket: Ticket, cred_info: KrbCredInfo) -> Self
	{
		Self { ticket, cred_info }
	}

	pub fn as_bytes(&self, cred_format: CredFormat) -> Result<Vec<u8>>
	{
		let krb_cred: KrbCred = TicketCreds::new(vec![(*self).clone()]).into();

		match cred_format
		{
			CredFormat::Krb => Ok(krb_cred.build()),
			CredFormat::Ccache =>
			{
				let ccache: CCache = krb_cred.try_into()
				                             .map_err(|_| Error::DataError("Error converting KrbCred to CCache".to_string()))?;
				Ok(ccache.build())
			},
		}
	}

	pub fn from_bytes(vec: Vec<u8>) -> Result<Self>
	{
		match CCache::parse(&vec)
		{
			Ok((_, ccache)) =>
			{
				let krb_cred: KrbCred =
					ccache.try_into().map_err(|_| Error::DataError("Error parsing ccache data content".to_string()))?;

				Ok(TicketCreds::try_from(krb_cred)?.ticket_creds[0].clone())
			},
			Err(_) =>
			{
				let (_, krb_cred) = KrbCred::parse(&vec).map_err(|_| {
					                                        Error::DataError("Error parsing content of ccache/krb".to_string())
				                                        })?;

				Ok(TicketCreds::try_from(krb_cred)?.ticket_creds[0].clone())
			},
		}
	}

	pub fn is_tgt(&self) -> bool
	{
		if let Some(sname) = &self.cred_info.sname
		{
			if let Some(service) = sname.name_string.first()
			{
				return service == "krbtgt";
			}
		}
		false
	}

	pub fn is_tgt_for_realm(&self, realm: &str) -> bool
	{
		if self.is_tgt()
		{
			if let Some(tgt_realm) = self.service_host()
			{
				return tgt_realm.to_lowercase() == realm.to_lowercase();
			}
		}
		false
	}

	pub fn is_for_service(&self, service: &PrincipalName) -> bool
	{
		if let Some(srv) = self.service()
		{
			return srv == service;
		}
		false
	}

	pub fn service(&self) -> Option<&PrincipalName>
	{
		self.cred_info.sname.as_ref()
	}

	pub fn service_host(&self) -> Option<&String>
	{
		if let Some(sname) = &self.cred_info.sname
		{
			return sname.name_string.get(1);
		}
		None
	}

	pub fn change_sname(&mut self, sname: PrincipalName)
	{
		self.ticket.sname = sname.clone();
		self.cred_info.sname = Some(sname);
	}
}

impl From<(Ticket, KrbCredInfo)> for TicketCred
{
	fn from((t, kci): (Ticket, KrbCredInfo)) -> Self
	{
		Self::new(t, kci)
	}
}
