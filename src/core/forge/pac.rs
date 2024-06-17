use crate::core::Cipher;
use kerberos_constants::key_usages;
use ms_dtyp::{FILETIME, RID_DOMAIN_USERS};
use ms_pac::{
	GROUP_MEMBERSHIP, KERB_VALIDATION_INFO, NOT_EXPIRE_TIME, NOT_SET_TIME, PACTYPE, PAC_CLIENT_INFO, PAC_INFO_BUFFER,
	PAC_SIGNATURE_DATA, PISID,
};
use ms_samr::{
	SE_GROUP_ENABLED, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_MANDATORY, USER_DONT_EXPIRE_PASSWORD, USER_NORMAL_ACCOUNT,
};

pub fn new_signed_pac(username: &str,
                      user_rid: u32,
                      domain: &str,
                      domain_sid: PISID,
                      groups: &[u32],
                      logon_time: FILETIME,
                      cipher: &Cipher)
                      -> PACTYPE
{
	let mut pactype = new_pactype(username, user_rid, domain, domain_sid, groups, cipher.checksum_type(), logon_time);

	let raw_pactype = pactype.build();

	let server_sign = cipher.checksum(key_usages::KEY_USAGE_KERB_NON_KERB_CKSUM_SALT, &raw_pactype);
	let privsrv_sign = cipher.checksum(key_usages::KEY_USAGE_KERB_NON_KERB_CKSUM_SALT, &server_sign);

	let server_checksum = pactype.server_checksum_mut().unwrap();
	server_checksum.Signature = server_sign;

	let privsrv_checksum = pactype.privsrv_checksum_mut().unwrap();
	privsrv_checksum.Signature = privsrv_sign;

	pactype
}

fn new_pactype(username: &str,
               user_rid: u32,
               domain: &str,
               domain_sid: PISID,
               groups: &[u32],
               checksum_type: i32,
               logon_time: FILETIME)
               -> PACTYPE
{
	PACTYPE::from(vec![
		PAC_INFO_BUFFER::LOGON_INFO(new_kerb_validation_info(
			username,
			user_rid,
			domain,
			domain_sid,
			groups,
			logon_time.clone(),
		)),
		PAC_INFO_BUFFER::CLIENT_INFO(PAC_CLIENT_INFO::new(logon_time, username)),
		PAC_INFO_BUFFER::SERVER_CHECKSUM(new_pac_signature(checksum_type)),
		PAC_INFO_BUFFER::PRIVSRV_CHECKSUM(new_pac_signature(checksum_type)),
	])
}

fn new_pac_signature(etype: i32) -> PAC_SIGNATURE_DATA
{
	PAC_SIGNATURE_DATA::new_empty(etype)
}

fn new_kerb_validation_info(username: &str,
                            user_rid: u32,
                            domain: &str,
                            domain_sid: PISID,
                            groups: &[u32],
                            logon_time: FILETIME)
                            -> KERB_VALIDATION_INFO
{
	let mut kvi = KERB_VALIDATION_INFO { LogonTime: logon_time.clone(),
	                                     LogoffTime: NOT_EXPIRE_TIME.into(),
	                                     KickOffTime: NOT_EXPIRE_TIME.into(),
	                                     PasswordLastSet: logon_time,
	                                     PasswordCanChange: NOT_SET_TIME.into(),
	                                     PasswordMustChange: NOT_EXPIRE_TIME.into(),
	                                     EfectiveName: username.into(),
	                                     LogonCount: 500,
	                                     BadPasswordCount: 0,
	                                     UserId: user_rid,
	                                     PrimaryGroupId: RID_DOMAIN_USERS,
	                                     LogonDomainName: domain.to_uppercase().as_str().into(),
	                                     LogonDomainId: domain_sid,
	                                     UserAccountControl: USER_NORMAL_ACCOUNT | USER_DONT_EXPIRE_PASSWORD,
	                                     ..Default::default() };

	for group_id in groups.iter()
	{
		kvi.GroupIds
		   .push(GROUP_MEMBERSHIP::new(*group_id, SE_GROUP_MANDATORY | SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT));
	}

	kvi
}
