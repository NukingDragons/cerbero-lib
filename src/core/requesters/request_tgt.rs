use super::senders::send_recv_as;
use crate::{
	communication::KrbChannel,
	core::{
		forge::{build_as_req, extract_krb_cred_from_as_rep, KrbUser},
		Cipher, TicketCred,
	},
	error::Error,
	error::Result,
};
use kerberos_asn1::{AsRep, Asn1Object, EtypeInfo2, PaData};
use kerberos_crypto::Key;

/// Uses user credentials to request a TGT
pub fn request_tgt(user: KrbUser, user_key: &Key, etype: Option<i32>, channel: &dyn KrbChannel) -> Result<TicketCred>
{
	// Attempt to generate using the default salt method
	let mut cipher = Cipher::generate(user_key, &user, etype, None);

	let rep = match request_as_rep(user.clone(), Some(&cipher), None, channel)
	{
		Ok(r) => r,
		Err(Error::KrbError(e)) =>
		{
			let match_e = e.clone();
			match match_e.e_data
			{
				Some(data) =>
				{
					let (_, raw_data) = data.split_at(2);
					let pa_data = match PaData::parse(raw_data)
					{
						Ok((_, d)) => d,
						Err(e) => return Err(Error::String(format!("{}", e))),
					};

					match pa_data.padata_type
					{
						// EtypeInfo2
						19 =>
						{
							let etype_info_2_entries = match EtypeInfo2::parse(&pa_data.padata_value)
							{
								Ok((_, d)) => d,
								Err(e) => return Err(Error::String(format!("{}", e))),
							};

							let mut salt: String = "".to_string();

							for entry in etype_info_2_entries
							{
								if let Some(s) = entry.salt
								{
									salt = s;
									break;
								}
							}

							cipher = Cipher::generate(user_key, &user, None, Some(salt.as_bytes().to_vec()));

							request_as_rep(user.clone(), Some(&cipher), None, channel)?
						},
						_ => return Err(Error::KrbError(e)),
					}
				},
				None => return Err(Error::KrbError(e)),
			}
		},
		Err(e) => return Err(e),
	};

	extract_krb_cred_from_as_rep(rep, &cipher)
}

/// Uses user credentials to obtain an AS-REP response
pub fn request_as_rep(user: KrbUser,
                      cipher: Option<&Cipher>,
                      etypes: Option<Vec<i32>>,
                      channel: &dyn KrbChannel)
                      -> Result<AsRep>
{
	let as_req = build_as_req(user, cipher, etypes);
	send_recv_as(channel, &as_req)
}
