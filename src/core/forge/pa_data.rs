use super::principal_name::new_nt_principal;
use crate::core::{forge::KrbUser, Cipher};
use chrono::Utc;
use kerberos_asn1::{
	ApReq, Asn1Object, Authenticator, EncryptedData, PaData, PaEncTsEnc, PaForUser, PaPacOptions, Ticket,
};
use kerberos_constants::{
	checksum_types,
	key_usages::{KEY_USAGE_AS_REQ_TIMESTAMP, KEY_USAGE_KERB_NON_KERB_CKSUM_SALT, KEY_USAGE_TGS_REQ_AUTHEN},
	pa_data_types::{self, PA_FOR_USER, PA_PAC_OPTIONS, PA_TGS_REQ},
};

/// Helper to create a PA-DATA that contains a PA-REQ-ENC-PA-REP
pub fn new_pa_req_enc_pa_rep() -> PaData
{
	PaData::new(149, vec![])
}

/// Helper to create a PA-DATA that contains a PA-REQ-ENC-PA-REP
pub fn new_pa_as_freshness() -> PaData
{
	PaData::new(150, vec![])
}

/// Helper to create a PA-DATA that contains a PA-ENC-TS-ENC struct
pub fn new_pa_data_encrypted_timestamp(cipher: &Cipher) -> PaData
{
	let timestamp = PaEncTsEnc::from(Utc::now());
	let encrypted_timestamp = cipher.encrypt(KEY_USAGE_AS_REQ_TIMESTAMP, &timestamp.build());
	PaData::new(pa_data_types::PA_ENC_TIMESTAMP, EncryptedData::new(cipher.etype(), None, encrypted_timestamp).build())
}

/// Helper to create a PA-DATA that contains a PA-FOR-USER struct
/// used in S4U2Self
pub fn new_pa_data_pa_for_user(impersonate_user: KrbUser, cipher: &Cipher) -> PaData
{
	let pa_for_user = new_pa_for_user(impersonate_user, cipher);
	PaData::new(PA_FOR_USER, pa_for_user.build())
}

/// Helper to easily create a PA-FOR-USER struct used in S4U2Self
fn new_pa_for_user(user: KrbUser, cipher: &Cipher) -> PaForUser
{
	let mut pa_for_user = PaForUser { username: new_nt_principal(&user.name),
	                                  userrealm: user.realm,
	                                  auth_package: "Kerberos".to_string(),
	                                  ..Default::default() };

	let mut ck_value = pa_for_user.username.name_type.to_le_bytes().to_vec();
	ck_value.append(&mut pa_for_user.username.name_string[0].clone().into_bytes());
	ck_value.append(&mut pa_for_user.userrealm.clone().into_bytes());
	ck_value.append(&mut pa_for_user.auth_package.clone().into_bytes());

	let cksum = cipher.checksum_hmac_md5(KEY_USAGE_KERB_NON_KERB_CKSUM_SALT, &ck_value);

	pa_for_user.cksum.cksumtype = checksum_types::HMAC_MD5;
	pa_for_user.cksum.checksum = cksum;

	pa_for_user
}

/// Helper to create a PA-DATA that contains a PA-PAC-OPTIONS struct
/// used in S4U2Proxy
pub fn new_pa_data_pac_options(pac_options: u32) -> PaData
{
	let pac_options = PaPacOptions { kerberos_flags: pac_options.into() };

	PaData::new(PA_PAC_OPTIONS, pac_options.build())
}

/// Helper to create a PA-DATA that contains an AP-REQ struct
pub fn new_pa_data_ap_req(user: KrbUser, ticket: Ticket, cipher: &Cipher) -> PaData
{
	let authenticator = new_authenticator(user);

	let encrypted_authenticator = cipher.encrypt(KEY_USAGE_TGS_REQ_AUTHEN, &authenticator.build());

	let ap_req = new_ap_req(ticket, cipher.etype(), encrypted_authenticator);
	PaData::new(PA_TGS_REQ, ap_req.build())
}

/// Helper to create an encrypt an Authenticator struct
fn new_authenticator(user: KrbUser) -> Authenticator
{
	Authenticator { crealm: user.realm, cname: new_nt_principal(&user.name), ..Default::default() }
}

/// Helper to create an AP-REQ struct
fn new_ap_req(ticket: Ticket, etype: i32, cipher: Vec<u8>) -> ApReq
{
	ApReq { ticket, authenticator: EncryptedData { etype, kvno: None, cipher }, ..Default::default() }
}
