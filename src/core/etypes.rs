use kerberos_constants::etypes;

/// Valid encryption algorithms that can be sent to the server
#[derive(Debug, Clone)]
pub enum EncryptionType
{
	RC4,
	AES128,
	AES256,
}

impl EncryptionType
{
	/// Converts the encryption type into a `kerberos_constants::etypes` constant
	///
	/// # Examples
	/// ```
	/// assert_eq!(kerberos_constants::etypes::RC4_HMAC, EncryptionType::RC4.as_constant());
	/// ```
	pub fn as_constant(&self) -> i32
	{
		match self
		{
			Self::RC4 => etypes::RC4_HMAC,
			Self::AES128 => etypes::AES128_CTS_HMAC_SHA1_96,
			Self::AES256 => etypes::AES256_CTS_HMAC_SHA1_96,
		}
	}
}
