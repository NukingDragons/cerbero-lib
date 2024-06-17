use crate::{communication::KrbChannel, error::Result};
use kerberos_asn1::{AsRep, AsReq, Asn1Object, KrbError, TgsRep, TgsReq};
use std::io;

pub enum Rep
{
	AsRep(AsRep),
	TgsRep(TgsRep),
	KrbError(KrbError),
	Raw(Vec<u8>),
}

/// Send an array of bytes, which should be a kerberos request
/// coded in ASN1/DER format and retrieves the response, by parsing
/// it to a known Kerberos response
pub fn send_recv(channel: &dyn KrbChannel, raw: &[u8]) -> io::Result<Rep>
{
	let raw_rep = channel.send_recv(raw)?;

	if let Ok((_, krb_error)) = KrbError::parse(&raw_rep)
	{
		return Ok(Rep::KrbError(krb_error));
	}

	if let Ok((_, as_rep)) = AsRep::parse(&raw_rep)
	{
		return Ok(Rep::AsRep(as_rep));
	}

	if let Ok((_, rep)) = TgsRep::parse(&raw_rep)
	{
		return Ok(Rep::TgsRep(rep));
	}

	Ok(Rep::Raw(raw_rep))
}

/// Function to send a TGS-REQ message and receive a TGS-REP
pub fn send_recv_tgs(channel: &dyn KrbChannel, req: &TgsReq) -> Result<TgsRep>
{
	let rep =
		send_recv(channel, &req.build()).map_err(|err| (format!("Error sending TGS-REQ to {}", channel.ip()), err))?;

	match rep
	{
		Rep::KrbError(krb_error) => Err(krb_error)?,

		Rep::Raw(_) => Err("Error parsing response")?,

		Rep::AsRep(_) => Err("Unexpected: server responded with AS-REP to TGS-REQ")?,

		Rep::TgsRep(tgs_rep) => Ok(tgs_rep),
	}
}

/// Function to send an AS-REQ message and receive an AS-REP
pub fn send_recv_as(channel: &dyn KrbChannel, req: &AsReq) -> Result<AsRep>
{
	let rep =
		send_recv(channel, &req.build()).map_err(|err| (format!("Error sending AS-REQ to {}", channel.ip()), err))?;

	match rep
	{
		Rep::KrbError(krb_error) => Err(krb_error)?,

		Rep::Raw(_) => Err("Error parsing response")?,

		Rep::AsRep(as_rep) => Ok(as_rep),

		Rep::TgsRep(_) => Err("Unexpected: server responded with a TGS-REQ to an AS-REP")?,
	}
}
