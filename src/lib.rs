//! # cerbero-lib
//!
//! `cerbero-lib` is a library to perform several tasks related with Kerberos protocol in an Active Directory pentest.
//!
//! This repo was cloned from <https://gitlab.com/Zer1i0/cerbero> and has been converted into a library format.
//! I intend to add more features/clean up the code further, see the [TODO](#TODO) section.
//!
//! Each of the commands that the origin crate provides are exposed as functions in this library and have examples of usage
//!
//! There is also an examples directory that can be referenced at <https://github.com/NukingDragons/cerbero-lib/tree/main/examples>
//! The associated github can be found at <https://github.com/NukingDragons/cerbero-lib>

// TODO: Fix the issues causing these warnings instead of this lazy fix
#![allow(suspicious_double_ref_op)]
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
	error::Result,
};

pub use kerberos_asn1::Ticket;
pub use kerberos_crypto::Key;
pub use ms_pac::PISID;
