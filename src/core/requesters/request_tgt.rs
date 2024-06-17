use super::senders::send_recv_as;
use crate::{
	communication::KrbChannel,
	core::{
		forge::{build_as_req, extract_krb_cred_from_as_rep, KrbUser},
		Cipher, TicketCred,
	},
	error::Result,
};
use kerberos_asn1::AsRep;
use kerberos_crypto::Key;

/// Uses user credentials to request a TGT
pub fn request_tgt(user: KrbUser, user_key: &Key, etype: Option<i32>, channel: &dyn KrbChannel) -> Result<TicketCred>
{
	let cipher = Cipher::generate(user_key, &user, etype);

	let rep = request_as_rep(user.clone(), Some(&cipher), None, channel)?;
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
