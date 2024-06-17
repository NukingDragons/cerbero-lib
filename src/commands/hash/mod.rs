use crate::{core::KrbUser, Result};
use kerberos_crypto::{aes_hmac_sha1, rc4_hmac_md5, AesSizes};

/// Calculate the users NT (RC4) hash
///
/// # Examples
///
/// ```
/// let hash = hash_rc4("Password").expect("Failed to hash RC4 password");
/// ```
pub fn hash_rc4(password: &str) -> Result<String>
{
	let rc4_key = rc4_hmac_md5::generate_key_from_string(password);
	Ok(get_hex(&rc4_key))
}

/// Calculate the users aes128 key
///
/// # Examples
///
/// ```
/// let hash = hash_aes128("DOMAIN.COM", "Username", "Password").expect("Failed to hash AES128 password");
/// ```
pub fn hash_aes128(realm: &str, username: &str, password: &str) -> Result<String>
{
	let user = KrbUser::new(username.to_string(), realm.to_string());
	let aes_salt = aes_hmac_sha1::generate_salt(&user.realm, &user.name);

	let aes_128_key = aes_hmac_sha1::generate_key_from_string(password, &aes_salt, &AesSizes::Aes128);

	Ok(get_hex(&aes_128_key))
}

/// Calculate the users aes256 key
///
/// # Examples
///
/// ```
/// let hash = hash_aes256("DOMAIN.COM", "Username", "Password").expect("Failed to hash AES256 password");
/// ```
pub fn hash_aes256(realm: &str, username: &str, password: &str) -> Result<String>
{
	let user = KrbUser::new(username.to_string(), realm.to_string());
	let aes_salt = aes_hmac_sha1::generate_salt(&user.realm, &user.name);

	let aes_256_key = aes_hmac_sha1::generate_key_from_string(password, &aes_salt, &AesSizes::Aes256);

	Ok(get_hex(&aes_256_key))
}

fn get_hex(v: &[u8]) -> String
{
	let mut s = String::new();
	for x in v
	{
		s = format!("{}{:02x}", s, x)
	}

	s
}
