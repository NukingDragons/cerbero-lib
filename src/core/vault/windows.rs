use super::Vault;
use crate::{
	core::{CredFormat, TicketCred, TicketCreds},
	error::Error,
	KrbUser, Result,
};
use std::{
	cell::RefCell,
	ffi::c_void,
	mem::size_of_val,
	ptr::{copy_nonoverlapping, null_mut},
};
#[allow(unused_imports)]
use windows::Win32::{
	Foundation::{HANDLE, LUID, NTSTATUS},
	Security::Authentication::Identity::{
		LsaCallAuthenticationPackage, LsaConnectUntrusted, LsaEnumerateLogonSessions, LsaGetLogonSessionData,
		LsaLookupAuthenticationPackage, KERB_CRYPTO_KEY_TYPE, KERB_PROTOCOL_MESSAGE_TYPE, KERB_QUERY_TKT_CACHE_REQUEST,
		KERB_QUERY_TKT_CACHE_RESPONSE, KERB_RETRIEVE_TKT_REQUEST, KERB_RETRIEVE_TKT_RESPONSE, KERB_SUBMIT_TKT_REQUEST,
		KERB_TICKET_CACHE_INFO_EX, LSA_STRING, SECURITY_LOGON_SESSION_DATA,
	},
	System::WindowsProgramming::GetUserNameW,
};
use windows_core::{PSTR, PWSTR};

const KERBEROS_PACKAGE_NAME: LSA_STRING =
	LSA_STRING { Length: 8, MaximumLength: 9, Buffer: PSTR(b"kerberos\0" as *const u8 as *mut u8) };

/// Vault that interacts directly with LSA, tickets in this vault are accessible for the entire
/// logon session
pub struct WindowsVault
{
	ticket_creds: RefCell<TicketCreds>,
	luid: RefCell<Option<LUID>>,
}

impl WindowsVault
{
	/// Creates a new windows vault for a given logon UID (LUID)
	///
	/// # Examples
	///
	/// Create a vault for the current user's logon session
	///
	/// ```
	/// let mut vault = WindowsVault::new(None);
	/// ```
	///
	/// Create a vault for a specific user's logon session
	///
	/// ```
	/// let mut vault = WindowsVault::new(WindowsVault::get_luid("Username".to_string())?[0]);
	/// ```
	pub fn new(luid: Option<LUID>) -> Self
	{
		Self { ticket_creds: RefCell::new(TicketCreds::new(vec![])), luid: RefCell::new(luid) }
	}

	/// Change the LUID for this vault
	///
	/// # Examples
	///
	/// ```
	/// let mut vault = WindowsVault::new(None);
	/// vault.set_luid(Some(WindowsVault::get_luid("Username".to_string())?[0]));
	/// ```
	#[allow(dead_code)]
	fn set_luid(&self, luid: Option<LUID>)
	{
		let mut internal_luid = self.luid.borrow_mut();
		*internal_luid = luid;
	}

	/// Get the username for the current user
	///
	/// # Examples
	///
	/// ```
	/// let mut vault =
	/// WindowsVault::new(Some(WindowsVault::get_luid(WindowsVault::get_current_username()?)?[0]));
	/// ```
	#[allow(dead_code)]
	pub fn get_current_username() -> Result<String>
	{
		unsafe {
			let mut username_pwstr = PWSTR(null_mut());
			let mut username_len = 0;

			let _ = GetUserNameW(username_pwstr, &mut username_len);

			let mut username_raw: Vec<u16> = vec![0; username_len as usize];
			username_pwstr = PWSTR(username_raw.as_mut_ptr());

			if GetUserNameW(username_pwstr, &mut username_len).is_err()
			{
				return Err(Error::DataError("Failed to fetch the currently logged in username".to_string()));
			}

			match String::from_utf16(&username_raw)
			{
				Ok(string) => Ok(string.trim_end_matches('\0').to_string()),
				Err(e) => Err(Error::DataError(format!("Failed to convert PWSTR to String: {}", e))),
			}
		}
	}

	/// Obtain the set of LUID's for a given username
	///
	/// # Examples
	///
	/// ```
	/// for luid in WindowsVault::get_luid("Username".to_string())?.iter()
	/// {
	///     let mut vault = WindowsVault::new(Some(luid));
	/// }
	/// ```
	#[allow(dead_code)]
	pub fn get_luid(username: String) -> Result<Vec<LUID>>
	{
		unsafe {
			let mut logon_session_count = 0;
			let mut logon_sessions_raw: *mut LUID = null_mut();

			let mut result = LsaEnumerateLogonSessions(&mut logon_session_count, &mut logon_sessions_raw);

			if result.is_ok()
			{
				let mut luids: Vec<LUID> = vec![];

				for index in 0..logon_session_count
				{
					let luid = logon_sessions_raw.offset(index as isize);
					let mut logon_session_raw: *mut SECURITY_LOGON_SESSION_DATA = null_mut();

					result = LsaGetLogonSessionData(luid, &mut logon_session_raw);

					if result.is_ok()
					{
						let logon_session = *logon_session_raw;

						if pwstr_to_string(logon_session.UserName.Buffer, logon_session.UserName.Length / 2)?
						   == username
						{
							luids.push(logon_session.LogonId);
						}
					}
					else
					{
						continue;
					}
				}

				if !luids.is_empty()
				{
					Ok(luids)
				}
				else
				{
					Err(Error::DataError("Failed to find current LUID".to_string()))
				}
			}
			else
			{
				Err(Error::DataError(format!("Failed to enumerate logon sessions: {:x}", result.0)))
			}
		}
	}
}

impl Default for WindowsVault
{
	fn default() -> Self
	{
		Self::new(None)
	}
}

impl Vault for WindowsVault
{
	fn id(&self) -> &str
	{
		"LSA"
	}

	fn support_cred_format(&self) -> Result<Option<CredFormat>>
	{
		Ok(Some(CredFormat::Krb))
	}

	fn add(&mut self, ticket_info: TicketCred) -> Result<()>
	{
		let luid = *self.luid.borrow();
		let mut ticket_creds = self.ticket_creds.borrow_mut();

		ticket_creds.push(ticket_info.clone());
		import_ticket(ticket_info, luid)
	}

	fn dump(&self) -> Result<TicketCreds>
	{
		//let luid = *self.luid.borrow();
		let ticket_creds = self.ticket_creds.borrow();

		// TODO: Use this
		//if let Ok(tickets) = dump_tickets(luid)
		//{
		//	*ticket_creds = tickets;
		//}

		Ok((*ticket_creds).clone())
	}

	fn save(&self, tickets: TicketCreds) -> Result<()>
	{
		let luid = *self.luid.borrow();

		for ticket in tickets.iter()
		{
			import_ticket(ticket.clone(), luid)?;
		}

		Ok(())
	}

	fn save_as(&self, tickets: TicketCreds, _: CredFormat) -> Result<()>
	{
		self.save(tickets)
	}

	fn change_format(&self, _: CredFormat) -> Result<()>
	{
		Ok(())
	}

	fn get_user_tgts(&self, user: &KrbUser) -> Result<TicketCreds>
	{
		let ticket_creds = self.dump()?;
		Ok(ticket_creds.user_tgt_realm(user, &user.realm))
	}

	fn s4u2self_tgss(&self,
	                 user: &KrbUser,
	                 impersonate_user: &KrbUser,
	                 user_service: Option<&String>)
	                 -> Result<TicketCreds>
	{
		let ticket_creds = self.dump()?;
		Ok(ticket_creds.s4u2self_tgss(user, impersonate_user, user_service))
	}
}

/// Import a ticket using LSA and optionally a LUID
fn import_ticket(ticket: TicketCred, luid: Option<LUID>) -> Result<()>
{
	let mut ticket_raw = ticket.as_bytes(CredFormat::Krb)?;

	unsafe {
		let mut lsa_handle = HANDLE::default();
		let mut result = LsaConnectUntrusted(&mut lsa_handle);

		if result.is_ok()
		{
			let mut authentication_package: u32 = 0;
			result = LsaLookupAuthenticationPackage(lsa_handle, &KERBEROS_PACKAGE_NAME, &mut authentication_package);

			if result.is_ok()
			{
				// KERB_PROTOCOL_MESSAGE_TYPE(21) == KerbSubmitticketMessage
				let mut request = KERB_SUBMIT_TKT_REQUEST { MessageType: KERB_PROTOCOL_MESSAGE_TYPE(21),
				                                            KerbCredSize: ticket_raw.len() as u32,
				                                            ..Default::default() };
				request.KerbCredOffset = size_of_val(&request) as u32;

				if let Some(l) = luid
				{
					request.LogonId = l;
				}

				let mut input_buffer: Vec<u8> = vec![0; request.KerbCredOffset as usize];
				copy_nonoverlapping(
				                    &request as *const KERB_SUBMIT_TKT_REQUEST as *const u8,
				                    input_buffer.as_mut_ptr(),
				                    request.KerbCredOffset as usize,
				);
				input_buffer.append(&mut ticket_raw);

				let mut result2: i32 = 0;

				result = LsaCallAuthenticationPackage(
				                                      lsa_handle,
				                                      authentication_package,
				                                      input_buffer.as_ptr() as *const c_void,
				                                      input_buffer.len() as u32,
				                                      None,
				                                      None,
				                                      Some(&mut result2),
				);

				if result.is_ok()
				{
					result = NTSTATUS(result2);

					if result.is_ok()
					{
						Ok(())
					}
					else
					{
						Err(Error::DataError(format!("Failed to complete protocol with error: {:x}", result.0)))
					}
				}
				else
				{
					Err(Error::DataError(format!("Failed to call authentication package with error: {:x}", result.0)))
				}
			}
			else
			{
				Err(Error::DataError(format!("Failed to lookup the authentication package with error: {:x}", result.0)))
			}
		}
		else
		{
			Err(Error::DataError(format!("Failed to connect to LSA with error: {:x}", result.0)))
		}
	}
}

// TODO: Ensure this works with the right privileges and to use this in the future
//pub fn dump_tickets(luid: Option<LUID>) -> Result<TicketCreds>
//{
//	unsafe {
//		let mut lsa_handle = HANDLE::default();
//		let mut result = LsaConnectUntrusted(&mut lsa_handle);
//
//		if result.is_ok()
//		{
//			let mut authentication_package: u32 = 0;
//			result = LsaLookupAuthenticationPackage(lsa_handle, &KERBEROS_PACKAGE_NAME, &mut authentication_package);
//
//			if result.is_ok()
//			{
//				// KERB_PROTOCOL_MESSAGE_TYPE(14) == KerbQueryTktCacheExMessage
//				let mut query_request =
//					KERB_QUERY_TKT_CACHE_REQUEST { MessageType: KERB_PROTOCOL_MESSAGE_TYPE(14), ..Default::default() };
//
//				// KERB_PROTOCOL_MESSAGE_TYPE(8) == KerbRetrieveEncodedTicketMessage
//				let mut ticket_request = KERB_RETRIEVE_TKT_REQUEST { MessageType: KERB_PROTOCOL_MESSAGE_TYPE(8),
//				                                                     CacheOptions: 8,
//				                                                     EncryptionType: KERB_CRYPTO_KEY_TYPE(18),
//				                                                     ..Default::default() };
//
//				if let Some(l) = luid
//				{
//					query_request.LogonId = l;
//					ticket_request.LogonId = l;
//				}
//
//				let mut tickets_info_ptr = null_mut();
//				let mut result2: i32 = 0;
//
//				result = LsaCallAuthenticationPackage(
//				                                      lsa_handle,
//				                                      authentication_package,
//				                                      &query_request as *const KERB_QUERY_TKT_CACHE_REQUEST
//				                                      as *const c_void,
//				                                      size_of_val(&query_request) as u32,
//				                                      Some(&mut tickets_info_ptr),
//				                                      None,
//				                                      Some(&mut result2),
//				);
//
//				if result.is_ok()
//				{
//					result = NTSTATUS(result2);
//
//					if result.is_ok()
//					{
//						if !tickets_info_ptr.is_null()
//						{
//							let mut query_response = KERB_QUERY_TKT_CACHE_RESPONSE::default();
//							copy_nonoverlapping(
//							                    tickets_info_ptr,
//							                    &mut query_response as *mut KERB_QUERY_TKT_CACHE_RESPONSE
//							                    as *mut c_void,
//							                    size_of_val(&query_response),
//							);
//
//							let mut result_tickets = TicketCreds::new(vec![]);
//							let mut prev = KERB_TICKET_CACHE_INFO_EX::default();
//							for index in 0..query_response.CountOfTickets
//							{
//								let ticket_cache_info =
//									*(query_response.Tickets.as_ptr().byte_add(index as usize * size_of_val(&prev))
//									  as *const KERB_TICKET_CACHE_INFO_EX);
//								prev = ticket_cache_info;
//								//println!("{}/{}: {:?}", index + 1, query_response.CountOfTickets, ticket_cache_info);
//
//								if ticket_cache_info.ServerName.MaximumLength == 0
//								{
//									continue;
//								}
//
//								ticket_request.TargetName = ticket_cache_info.ServerName;
//
//								let ticket_request_size = size_of_val(&ticket_request);
//								let mut input_buffer: Vec<u8> =
//									vec![0; ticket_request_size + (ticket_request.TargetName.MaximumLength as usize)];
//								copy_nonoverlapping(
//								                    ticket_request.TargetName.Buffer.0 as *const u8,
//								                    input_buffer.as_mut_ptr().add(ticket_request_size),
//								                    ticket_request.TargetName.MaximumLength as usize,
//								);
//								ticket_request.TargetName.Buffer.0 =
//									input_buffer.as_mut_ptr().add(ticket_request_size) as *mut u16;
//								copy_nonoverlapping(
//								                    &ticket_request as *const KERB_RETRIEVE_TKT_REQUEST as *const u8,
//								                    input_buffer.as_mut_ptr(),
//								                    ticket_request_size,
//								);
//
//								let mut tickets_ptr = null_mut();
//								result = LsaCallAuthenticationPackage(
//								                                      lsa_handle,
//								                                      authentication_package,
//								                                      input_buffer.as_ptr() as *const c_void,
//								                                      input_buffer.len() as u32,
//								                                      Some(&mut tickets_ptr),
//								                                      None,
//								                                      Some(&mut result2),
//								);
//
//								if result.is_ok()
//								{
//									result = NTSTATUS(result2);
//
//									if result.is_ok()
//									{
//										let mut ticket_response = KERB_RETRIEVE_TKT_RESPONSE::default();
//										copy_nonoverlapping(
//										                    tickets_ptr,
//										                    &mut ticket_response as *mut KERB_RETRIEVE_TKT_RESPONSE
//										                    as *mut c_void,
//										                    size_of_val(&ticket_response),
//										);
//
//										let mut ticket_raw: Vec<u8> =
//											vec![0; ticket_response.Ticket.EncodedTicketSize as usize];
//
//										copy_nonoverlapping(
//										                    ticket_response.Ticket.EncodedTicket,
//										                    ticket_raw.as_mut_ptr(),
//										                    ticket_response.Ticket.EncodedTicketSize as usize,
//										);
//
//										let ticket = TicketCred::from_bytes(ticket_raw)?;
//
//										// Session keys are not returned if in a non-elevated context
//										// Do NOT return these tickets otherwise KRB_AP_ERR_BAD_INTEGRITY ensues
//										for byte in ticket.cred_info.key.keyvalue.iter()
//										{
//											if *byte != 0
//											{
//												result_tickets.push(ticket);
//												break;
//											}
//										}
//									}
//									else
//									{
//										return Err(Error::DataError(format!(
//											"Failed to complete protocol with error: {:x}",
//											result.0
//										)));
//									}
//								}
//								else
//								{
//									return Err(Error::DataError(format!(
//										"Failed to call authentication package with error: {:x}",
//										result.0
//									)));
//								}
//							}
//
//							Ok(result_tickets)
//						}
//						else
//						{
//							Ok(TicketCreds::new(vec![]))
//						}
//					}
//					else
//					{
//						Err(Error::DataError(format!("Failed to complete protocol with error: {:x}", result.0)))
//					}
//				}
//				else
//				{
//					Err(Error::DataError(format!("Failed to call authentication package with error: {:x}", result.0)))
//				}
//			}
//			else
//			{
//				Err(Error::DataError(format!("Failed to lookup the authentication package with error: {:x}", result.0)))
//			}
//		}
//		else
//		{
//			Err(Error::DataError(format!("Failed to connect to LSA with error: {:x}", result.0)))
//		}
//	}
//}

fn pwstr_to_string(pwstr: PWSTR, len: u16) -> Result<String>
{
	let mut pwstr_raw: Vec<u16> = vec![0; len as usize];
	unsafe {
		copy_nonoverlapping(pwstr.0, pwstr_raw.as_mut_ptr(), len as usize);
	}

	match String::from_utf16(&pwstr_raw)
	{
		Ok(string) => Ok(string),
		Err(e) => Err(Error::DataError(format!("Faield to convert PWSTR to String: {}", e))),
	}
}
