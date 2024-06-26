//! Module to provide means to transport Kerberos messages
//!

mod channel_trait;
pub use channel_trait::KrbChannel;

mod tcp_channel;
use tcp_channel::TcpChannel;

mod udp_channel;
use udp_channel::UdpChannel;

use crate::Result;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use trust_dns_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use trust_dns_resolver::Resolver;

/// Transport protocols available to send Kerberos messages
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum TransportProtocol
{
	TCP,
	UDP,
}

/// Struct to package KDC's
#[derive(Debug, Clone)]
pub struct Kdcs
{
	kdcs: HashMap<String, IpAddr>,
}

impl Default for Kdcs
{
	fn default() -> Self
	{
		Self::new()
	}
}

impl Kdcs
{
	pub fn new() -> Self
	{
		Self { kdcs: HashMap::new() }
	}

	/// # Examples
	///
	/// ```
	/// let mut kdcs = Kdcs::new();
	/// let realm_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
	/// kdcs.insert("realm.com", realm_ip);
	/// ```
	pub fn insert(&mut self, realm: String, ip: IpAddr)
	{
		self.kdcs.insert(realm.to_lowercase(), ip);
	}

	pub fn get(&self, realm: &str) -> Option<&IpAddr>
	{
		self.kdcs.get(&realm.to_lowercase())
	}

	pub fn ips(&self) -> Vec<&IpAddr>
	{
		self.kdcs.values().collect()
	}

	pub fn get_clone(&self, realm: &str) -> Option<IpAddr>
	{
		self.get(realm).copied()
	}
}

/// Struct to package the KDC's and the protocol to communicate with them
#[derive(Clone)]
pub struct KdcComm
{
	kdcs: Kdcs,
	protocol: TransportProtocol,
}

impl KdcComm
{
	/// Create a new KdcComm struct
	///
	/// # Examples
	/// ```
	/// let mut kdcs = Kdcs::new();
	/// let kdc_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
	/// kdcs.insert("DOMAIN.COM".to_string(), kdc_ip);
	///
	/// let kdccomm = KdcComm::new(kdcs, TransportProtocol::TCP);
	/// ```
	pub fn new(kdcs: Kdcs, protocol: TransportProtocol) -> Self
	{
		Self { kdcs, protocol }
	}

	/// Create a KrbChannel for the KDC specified by it's realm
	///
	/// # Examples
	///
	/// ```
	/// let mut kdcs = Kdcs::new();
	/// let kdc_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
	/// kdcs.insert("DOMAIN.COM".to_string(), kdc_ip);
	///
	/// let kdccomm = KdcComm::new(kdcs, TransportProtocol::TCP);
	/// let channel = kdccomm.create_channel("DOMAIN.COM")?;
	/// ```
	pub fn create_channel(&mut self, realm: &str) -> Result<Box<dyn KrbChannel>>
	{
		resolve_krb_channel(realm, &mut self.kdcs, self.protocol)
	}
}

const KERBEROS_PORT: u16 = 88;
/// Generates a transporter given and address and transport protocol
pub fn new_krb_channel(dst_ip: IpAddr, transport_protocol: TransportProtocol) -> Box<dyn KrbChannel>
{
	let dst_address = SocketAddr::new(dst_ip, KERBEROS_PORT);
	match transport_protocol
	{
		TransportProtocol::TCP => Box::new(TcpChannel::new(dst_address)),
		TransportProtocol::UDP => Box::new(UdpChannel::new(dst_address)),
	}
}

pub fn resolve_krb_channel(realm: &str,
                           kdcs: &mut Kdcs,
                           channel_protocol: TransportProtocol)
                           -> Result<Box<dyn KrbChannel>>
{
	let kdc_ip = resolve_kdc_ip(realm, kdcs)?;
	kdcs.insert(realm.to_string(), kdc_ip);

	Ok(new_krb_channel(kdc_ip, channel_protocol))
}

pub fn resolve_kdc_ip(realm: &str, kdcs: &Kdcs) -> Result<IpAddr>
{
	Ok(match kdcs.get_clone(realm)
	{
		Some(ip) => ip,
		None =>
		{
			let dns_servers = kdcs.ips().iter().map(|ip| SocketAddr::new(**ip, 53)).collect();
			resolve_host(realm, dns_servers)?
		},
	})
}

pub fn resolve_host(realm: &str, dns_servers: Vec<SocketAddr>) -> Result<IpAddr>
{
	let resolver = if dns_servers.is_empty()
	{
		Resolver::from_system_conf().map_err(|err| format!("Unable to use dns system configuration: {}", err))?
	}
	else
	{
		let mut resolver_config = ResolverConfig::new();
		for server in dns_servers
		{
			resolver_config.add_name_server(NameServerConfig { socket_addr: server,
			                                                   protocol: Protocol::Tcp,
			                                                   tls_dns_name: None,
			                                                   trust_nx_responses: false });
		}
		Resolver::new(resolver_config, ResolverOpts::default()).unwrap()
	};

	let ips = resolver.lookup_ip(realm).map_err(|err| format!("Error resolving '{}' : '{}'", realm, err))?;

	let ip = ips.iter().next().ok_or(format!("Error resolving '{}': No entries found", realm))?;

	Ok(ip)
}
