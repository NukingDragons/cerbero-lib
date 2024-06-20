//! # cerbero-lib

//! ```text
//!   ____          _                          _ _ _
//!  / ___|___ _ __| |__   ___ _ __ ___       | (_) |__
//! | |   / _ \ '__| '_ \ / _ \ '__/ _ \ _____| | | '_ \
//! | |__|  __/ |  | |_) |  __/ | | (_) |_____| | | |_) |
//!  \____\___|_|  |_.__/ \___|_|  \___/      |_|_|_.__/
//! ```
//!
//! Library to perform several tasks related with the Kerberos protocol in an Active Directory pentest.
//!
//! This repo was cloned from <https://gitlab.com/Zer1i0/cerbero> and has been converted into a library format.
//! I intend to add more features/clean up the code further -- view the
//! [TODO](https://github.com/NukingDragons/cerbero-lib/tree/main?tab=readme-ov-file#TODO) section
//! in the associated [github](https://github.com/NukingDragons/cerbero-lib).
//!
//! ## Table of Contents
//! 1. [**Installation**](#installation)
//! 2. [**Functions**](#functions)
//!     - [**ask**](#ask)
//!     - [**asreproast**](#asreproast)
//!     - [**brute**](#brute)
//!     - [**convert**](#convert)
//!     - [**craft**](#craft)
//!     - [**hash**](#hash)
//!     - [**kerberoast**](#kerberoast)
//! 3. [**TODO**](https://github.com/NukingDragons/cerbero-lib/tree/main?tab=readme-ov-file#TODO)
//! 4. [**Credits**](#credits)
//!
//! ---
//!
//! ## Installation
//!
//! To use this library in your project you can add it via `cargo add`:
//!
//! ```sh
//! cargo add cerbero-lib
//! ```
//!
//! ## Functions
//!
//! ### Ask
//! The [ask](fn.ask.html) function allows retrieval of Kerberos tickets (TGT/TGS) from the KDC
//! (Domain Controller in Active Directory environment). Moreover, it also
//! perform requests to obtain tickets by using the S4U2Self and S4U2Proxy
//! Kerberos extensions.
//!
//! _(View the `ask` example [here](https://github.com/NukingDragons/cerbero-lib/tree/main/examples/ask/src/main.rs))_
//!
//! ### AsRepRoast
//! The [asreproast](fn.asreproast.html) function can be used to discover users that do not require
//! pre-authentication and retrieve a ticket to crack with hashcat or john.
//!
//! _(View the `asreproast` example [here](https://github.com/NukingDragons/cerbero-lib/tree/main/examples/asreproast/src/main.rs))_
//!
//! ### Brute
//! The [brute](fn.brute.html) function performs TGT requests in order to discover user credentials
//! based on the KDC response. This bruteforce technique allows you to discover:
//! + Valid username/password pairs
//! + Valid usernames
//! + Expired passwords
//! + Blocked or disabled users
//!
//! This attack should be performed carefully since can block user
//! accounts in case of perform many incorrect authentication attemps
//! for the same user.
//!
//! _(View the `brute` example [here](https://github.com/NukingDragons/cerbero-lib/tree/main/examples/brute/src/main.rs))_
//!
//! ### Convert
//! The [convert](fn.convert.html) function will convert ticket files between krb (Windows)
//! and ccache (Linux) formats.
//!
//! _(View the `convert` example [here](https://github.com/NukingDragons/cerbero-lib/tree/main/examples/convert/src/main.rs))_
//!
//! ### Craft
//! The [craft](fn.craft.html) function allows for the crafting of golden and silver tickets.
//!
//! _(View the `craft` example [here](https://github.com/NukingDragons/cerbero-lib/tree/main/examples/craft/src/main.rs))_
//!
//! ### Hash
//! The [hash](hash/index.html) module contains functions that calculate the Kerberos keys (password hashes) from the user password.
//!
//! _(View the `hash` example [here](https://github.com/NukingDragons/cerbero-lib/tree/main/examples/hash/src/main.rs))_
//!
//! ### Kerberoast
//! The [kerberoast](fn.kerberoast.html) function can be used to retrieve a (potentially crackable) password hash
//! for an account with an SPN set.
//!
//! To format encrypted part of tickets in order to be cracked by hashcat or john,
//! you need to provide a file with the user services. Each line of the file
//! must have one of the following formats:
//! * `user`
//! * `domain/user`
//! * `user:spn`
//! * `domain/user:spn`
//!
//! When a service [SPN](https://en.hackndo.com/service-principal-name-spn/)
//! is not specified, then a
//! [NT-ENTERPRISE principal](https://swarm.ptsecurity.com/kerberoasting-without-spns/)
//! is used. This can also be useful to bruteforce users with services.
//!
//! _(View the `kerberoast` example [here](https://github.com/NukingDragons/cerbero-lib/tree/main/examples/kerberoast/src/main.rs))_
//!
//! ## Credits
//! This work is based on great work of other people:
//! - [Impacket](https://github.com/SecureAuthCorp/impacket) of Alberto Solino [@agsolino](https://github.com/agsolino)
//! - [Rubeus](https://github.com/GhostPack/Rubeus) of Will [@harmj0y](https://twitter.com/harmj0y) and Elad Shamir [@elad_shamir](https://twitter.com/elad_shamir)
//! - [Mimikatz](https://github.com/gentilkiwi/mimikatz) of [@gentilkiwi](https://twitter.com/gentilkiwi)
//! - [Cerbero](https://gitlab.com/Zer1i0/cerbero) of Eloy [@zer1i0](zer1t0ps@protonmail.com)

// TODO: Fix the issues causing these warnings instead of this lazy fix
#![allow(deprecated)]
#![allow(clippy::too_many_arguments)]

mod commands;
mod communication;
mod core;
mod error;

/// Utilities for converting various things in this crate into strings
pub use crate::core::stringifier;

/// The file formats for tickets (KRB/CCache)
pub use crate::core::CredFormat;

pub use crate::{
	commands::{ask, asreproast, brute, convert, craft, hash, kerberoast},
	communication::{KdcComm, Kdcs, KrbChannel, TransportProtocol},
	core::{
		BruteResult, BufVault, CrackFormat, EmptyVault, EncryptionType, FileVault, KrbUser, TicketCred, TicketCreds,
		Vault,
	},
	error::{Error, Result},
};

pub use kerberos_asn1::Ticket;
pub use kerberos_crypto::Key;

#[cfg(target_os = "windows")]
pub use crate::core::WindowsVault;
