use cerbero_lib::hash::{hash_aes128, hash_aes256, hash_rc4};

fn main()
{
	println!("RC4 Hash: {}", hash_rc4("Password").expect("Failed to hash RC4 password"));
	println!(
	         "AES128 Hash: {}",
	         hash_aes128("DOMAIN.COM", "Username", "Password").expect("Failed to hash AES128 password")
	);
	println!(
	         "AES256 Hash: {}",
	         hash_aes256("DOMAIN.COM", "Username", "Password").expect("Failed to hash AES256 password")
	);
}
