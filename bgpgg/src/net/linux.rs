// Copyright 2026 bgpgg Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

pub use super::utils::set_ttl_max;
use super::utils::{setsockopt, TTL_MAX};
use std::io;
use std::mem;
use std::net::IpAddr;
use std::os::unix::io::RawFd;
use std::ptr::addr_of_mut;

/// struct tcp_md5sig (linux/tcp.h)
#[repr(C)]
struct TcpMd5sig {
    peer_addr: libc::sockaddr_storage,     // tcpm_addr
    flags: u8,                             // tcpm_flags: 0 for basic use
    prefixlen: u8,                         // tcpm_prefixlen: 0 = exact IP match
    keylen: u16,                           // tcpm_keylen
    ifindex: i32,                          // tcpm_ifindex: 0 = any interface
    key: [u8; libc::TCP_MD5SIG_MAXKEYLEN], // tcpm_key
}

// Builds a TcpMd5sig to pass to setsockopt(TCP_MD5SIG). The struct layout
// mirrors linux/tcp.h and is interpreted directly by the kernel.
fn tcp_md5sig(peer_addr: IpAddr, key: &[u8]) -> TcpMd5sig {
    let mut sig: TcpMd5sig = unsafe { mem::zeroed() };
    sig.keylen = key.len() as u16;
    sig.key[..key.len()].copy_from_slice(key);

    match peer_addr {
        // sin_port is left zero; the kernel matches MD5 keys by IP address only.
        IpAddr::V4(v4) => unsafe {
            let sa = addr_of_mut!(sig.peer_addr) as *mut libc::sockaddr_in;
            (*sa).sin_family = libc::AF_INET as u16;
            // octets() is already in network byte order; from_ne_bytes copies
            // the bytes as-is into s_addr without reordering.
            (*sa).sin_addr.s_addr = u32::from_ne_bytes(v4.octets());
        },
        IpAddr::V6(v6) => unsafe {
            let sa = addr_of_mut!(sig.peer_addr) as *mut libc::sockaddr_in6;
            (*sa).sin6_family = libc::AF_INET6 as u16;
            (*sa).sin6_addr.s6_addr = v6.octets();
        },
    }

    sig
}

/// Enable GTSM (RFC 5082) on a socket for the given peer address.
///
/// Sets outgoing TTL to 255 (RFC 5082: sender must use TTL=255) and enforces
/// a minimum inbound TTL so that packets arriving with TTL < min_ttl are
/// dropped by the kernel.
pub fn apply_gtsm(fd: RawFd, addr: IpAddr, min_ttl: u8) -> io::Result<()> {
    match addr {
        IpAddr::V4(_) => {
            setsockopt(fd, libc::IPPROTO_IP, libc::IP_TTL, TTL_MAX)?;
            setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_MINTTL,
                min_ttl as libc::c_int,
            )?;
        }
        IpAddr::V6(_) => {
            setsockopt(fd, libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS, TTL_MAX)?;
            setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_MINHOPCOUNT,
                min_ttl as libc::c_int,
            )?;
        }
    }
    Ok(())
}

/// Set TCP MD5 signature key on a socket for the given peer address (RFC 2385).
pub fn apply_tcp_md5(fd: RawFd, peer_addr: IpAddr, key: &[u8]) -> io::Result<()> {
    if key.len() > libc::TCP_MD5SIG_MAXKEYLEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "MD5 key too long (max 80 bytes)",
        ));
    }
    let sig = tcp_md5sig(peer_addr, key);
    setsockopt(fd, libc::IPPROTO_TCP, libc::TCP_MD5SIG, sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::utils::getsockopt_int;
    use std::net::Ipv4Addr;
    use std::os::unix::io::AsRawFd;
    use std::ptr::addr_of;
    use tokio::net::TcpSocket;

    #[test]
    fn test_tcp_md5sig() {
        let key = b"secret";
        let cases: &[(IpAddr, u16, u32)] = &[
            (
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                libc::AF_INET as u16,
                u32::from_ne_bytes([10, 0, 0, 1]),
            ),
            (
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                libc::AF_INET as u16,
                u32::from_ne_bytes([192, 168, 1, 1]),
            ),
        ];
        for (addr, expected_family, expected_s_addr) in cases {
            let sig = tcp_md5sig(*addr, key);
            assert_eq!(sig.keylen, key.len() as u16);
            assert_eq!(&sig.key[..key.len()], key.as_slice());
            unsafe {
                let sa = addr_of!(sig.peer_addr) as *const libc::sockaddr_in;
                assert_eq!((*sa).sin_family, *expected_family);
                assert_eq!((*sa).sin_addr.s_addr, *expected_s_addr);
            }
        }
    }

    #[test]
    fn test_apply_tcp_md5_key_too_long() {
        let socket = TcpSocket::new_v4().unwrap();
        let peer_addr: IpAddr = "127.0.0.1".parse().unwrap();
        let key = vec![0u8; 81]; // exceeds TCP_MD5SIG_MAXKEYLEN
        let result = apply_tcp_md5(socket.as_raw_fd(), peer_addr, &key);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn test_apply_tcp_md5_v4() {
        let socket = TcpSocket::new_v4().unwrap();
        let peer_addr: IpAddr = "127.0.0.1".parse().unwrap();
        let key = b"test-bgp-md5-key";
        let result = apply_tcp_md5(socket.as_raw_fd(), peer_addr, key);
        assert!(result.is_ok(), "apply_tcp_md5 failed: {:?}", result.err());
    }

    #[test]
    fn test_apply_gtsm_v4() {
        for min_ttl in [255u8, 254] {
            let socket = TcpSocket::new_v4().unwrap();
            let fd = socket.as_raw_fd();
            apply_gtsm(fd, "127.0.0.1".parse().unwrap(), min_ttl).unwrap();
            assert_eq!(getsockopt_int(fd, libc::IPPROTO_IP, libc::IP_TTL), TTL_MAX);
            assert_eq!(
                getsockopt_int(fd, libc::IPPROTO_IP, libc::IP_MINTTL),
                min_ttl as libc::c_int,
            );
        }
    }

    #[test]
    fn test_apply_gtsm_v6() {
        let socket = TcpSocket::new_v6().unwrap();
        let fd = socket.as_raw_fd();
        apply_gtsm(fd, "::1".parse().unwrap(), 254).unwrap();
        assert_eq!(
            getsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS),
            TTL_MAX,
        );
        assert_eq!(
            getsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_MINHOPCOUNT),
            254,
        );
    }

    #[test]
    fn test_set_ttl_max() {
        let socket = TcpSocket::new_v4().unwrap();
        set_ttl_max(socket.as_raw_fd(), "127.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(
            getsockopt_int(socket.as_raw_fd(), libc::IPPROTO_IP, libc::IP_TTL),
            TTL_MAX
        );

        let socket = TcpSocket::new_v6().unwrap();
        set_ttl_max(socket.as_raw_fd(), "::1".parse().unwrap()).unwrap();
        assert_eq!(
            getsockopt_int(
                socket.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_UNICAST_HOPS
            ),
            TTL_MAX,
        );
    }
}
