use crate::communication::{KrbChannel, TransportProtocol};
use std::{
	io::{self, Read, Write},
	net::{IpAddr, SocketAddr, TcpStream},
	time::Duration,
};

/// Send Kerberos messages over TCP
#[derive(Debug)]
pub struct TcpChannel
{
	dst_addr: SocketAddr,
}

impl TcpChannel
{
	pub fn new(dst_addr: SocketAddr) -> Self
	{
		Self { dst_addr }
	}
}

impl KrbChannel for TcpChannel
{
	fn send_recv(&self, raw: &[u8]) -> io::Result<Vec<u8>>
	{
		send_recv_tcp(&self.dst_addr, raw)
	}

	fn protocol(&self) -> TransportProtocol
	{
		TransportProtocol::TCP
	}

	fn ip(&self) -> IpAddr
	{
		self.dst_addr.ip()
	}
}

pub fn send_recv_tcp(dst_addr: &SocketAddr, raw: &[u8]) -> io::Result<Vec<u8>>
{
	let mut tcp_stream = TcpStream::connect_timeout(dst_addr, Duration::new(5, 0))?;

	let raw_sized_request = set_size_header_to_request(raw);
	tcp_stream.write_all(&raw_sized_request)?;

	let mut len_data_bytes = [0_u8; 4];
	tcp_stream.read_exact(&mut len_data_bytes)?;
	let data_length = u32::from_be_bytes(len_data_bytes);

	let mut raw_response: Vec<u8> = vec![0; data_length as usize];
	tcp_stream.read_exact(&mut raw_response)?;

	Ok(raw_response)
}

fn set_size_header_to_request(raw_request: &[u8]) -> Vec<u8>
{
	let request_length = raw_request.len() as u32;
	let mut raw_sized_request: Vec<u8> = request_length.to_be_bytes().to_vec();
	raw_sized_request.append(&mut raw_request.to_vec());

	raw_sized_request
}

#[cfg(test)]
mod tests
{
	use super::*;
	use std::net::Ipv4Addr;

	#[should_panic(expected = "NetworkError")]
	#[test]
	fn test_request_networks_error()
	{
		let requester = TcpChannel::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 88));
		requester.send_recv(&vec![]).unwrap();
	}
}
