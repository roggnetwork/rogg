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
use crate::log::warn;
use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::io::RawFd;
use std::ptr::{addr_of, addr_of_mut};

// IP_MINTTL is not exported by libc for FreeBSD (sys/netinet/in.h: IP_MINTTL = 66).
const IP_MINTTL: libc::c_int = 66;

/// Enable GTSM (RFC 5082) on a socket for the given peer address.
///
/// Sets outgoing TTL to 255 and enforces a minimum inbound TTL for IPv4.
/// IPv6 inbound hop-count filtering is not available on this platform
/// (FreeBSD lacks IPV6_MINHOPCOUNT); only the outgoing hop count is set.
pub fn apply_gtsm(fd: RawFd, addr: IpAddr, min_ttl: u8) -> io::Result<()> {
    match addr {
        IpAddr::V4(_) => {
            setsockopt(fd, libc::IPPROTO_IP, libc::IP_TTL, TTL_MAX)?;
            setsockopt(fd, libc::IPPROTO_IP, IP_MINTTL, min_ttl as libc::c_int)?;
        }
        IpAddr::V6(_) => {
            warn!("IPv6 GTSM inbound filtering is not supported on this platform");
            setsockopt(fd, libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS, TTL_MAX)?;
        }
    }
    Ok(())
}

// Constants from <sys/net/pfkeyv2.h> and <sys/netipsec/ipsec.h>
const PF_KEY_V2: libc::c_int = 2;
// FreeBSD requires SPI=0x1000 for TCP-MD5 (tcp(4)).
const TCP_SIG_SPI: u32 = 0x1000;
// SA state for SADB_ADD (RFC 2367 section 3.1.3).
const SADB_SASTATE_MATURE: u8 = 1;
// SADB message types (sadb_msg.sadb_msg_type): add or remove an SA.
const SADB_ADD: u8 = 3;
const SADB_DELETE: u8 = 4;
// SA type for TCP MD5 (sadb_msg.sadb_msg_satype). Not an IPsec SA type; this
// is a FreeBSD extension that hooks TCP MD5 into the SADB machinery.
const SADB_X_SATYPE_TCPSIGNATURE: u8 = 11;
// Extension type codes (sadb_ext.sadb_ext_type) identify each chunk in the
// flat SADB message buffer that follows the header.
const SADB_EXT_SA: u16 = 1; // sadb_sa: SPI, auth/encrypt algorithm, flags
const SADB_EXT_KEY_AUTH: u16 = 8; // sadb_key: authentication key bytes
const SADB_EXT_ADDRESS_SRC: u16 = 5; // sadb_address: source address selector
const SADB_EXT_ADDRESS_DST: u16 = 6; // sadb_address: destination address selector
const SADB_X_EXT_SA2: u16 = 19; // sadb_x_sa2: IPsec mode extension

// SA flags (sadb_sa.sadb_sa_flags)
const SADB_X_EXT_CYCSEQ: u32 = 0x0040; // Allow cyclic sequence numbers

// Authentication algorithm for TCP MD5 (sadb_sa.sadb_sa_auth). Value 252 is
// a FreeBSD-specific extension; not a standard SADB_AALG_* value.
const SADB_X_AALG_TCP_MD5: u8 = 252;
// No encryption algorithm (sadb_sa.sadb_sa_encrypt). TCP MD5 is auth-only.
const SADB_EALG_NONE: u8 = 0;
// Upper-layer protocol: match any. The SADB entry covers all TCP connections
// to the peer address; port filtering is not used for TCP MD5.
const IPSEC_ULPROTO_ANY: u8 = 255;
// IPsec mode: wildcard/any (netipsec/ipsec.h: IPSEC_MODE_ANY)
const IPSEC_MODE_ANY: u8 = 0;
// Maximum key length in bytes (tcp(4)). Same limit as Linux TCP_MD5SIG_MAXKEYLEN.
const TCP_MD5_MAXKEYLEN: usize = 80;

// SADB message header (RFC 2367 section 2.2, sys/net/pfkeyv2.h: sadb_msg). All len fields are in 64-bit units.
#[repr(C)]
struct SadbMsg {
    version: u8,
    msg_type: u8,
    errno: u8,
    satype: u8,
    len: u16,
    reserved: u16,
    seq: u32,
    pid: u32,
}

// SADB authentication/encryption key extension (sys/net/pfkeyv2.h: sadb_key).
// Immediately followed by key bytes, padded to 8 bytes.
#[repr(C)]
struct SadbKey {
    len: u16,
    exttype: u16,
    bits: u16,
    reserved: u16,
}

// SADB security association extension (sys/net/pfkeyv2.h: sadb_sa).
#[repr(C)]
struct SadbSa {
    len: u16,
    exttype: u16,
    spi: u32,
    replay: u8,
    state: u8,
    auth: u8,
    encrypt: u8,
    flags: u32,
}

// SADB address extension (sys/net/pfkeyv2.h: sadb_address).
// Immediately followed by a sockaddr, padded to 8 bytes.
#[repr(C)]
struct SadbAddress {
    len: u16,
    exttype: u16,
    proto: u8,
    prefixlen: u8,
    reserved: u16,
}

// SADB SA extension 2 (sys/net/pfkeyv2.h: sadb_x_sa2).
// FreeBSD extension for IPsec mode and sequence number handling.
#[repr(C)]
struct SadbXSa2 {
    len: u16,
    exttype: u16,
    mode: u8,
    reserved1: u8,
    reserved2: u16,
    sequence: u32,
    reqid: u32,
}

// Round up to 8-byte alignment (SADB extension boundary requirement)
fn pfkey_align8(n: usize) -> usize {
    (n + 7) & !7
}

// Convert byte length to SADB 64-bit units
fn pfkey_unit64(n: usize) -> u16 {
    (n / 8) as u16
}

// Pad buf to the next 8-byte boundary with zero bytes.
fn pad_to_8(buf: &mut Vec<u8>) {
    let rem = buf.len() % 8;
    if rem != 0 {
        buf.resize(buf.len() + (8 - rem), 0);
    }
}

// Append a struct's raw bytes to buf, then pad to 8-byte boundary.
unsafe fn push_struct<T: Sized>(buf: &mut Vec<u8>, val: T) {
    let bytes = std::slice::from_raw_parts(&val as *const T as *const u8, mem::size_of::<T>());
    buf.extend_from_slice(bytes);
    pad_to_8(buf);
}

// Append a sockaddr_in or sockaddr_in6 to buf, padded to 8 bytes.
unsafe fn push_sockaddr(buf: &mut Vec<u8>, addr: IpAddr) {
    match addr {
        IpAddr::V4(v4) => {
            let mut sa: libc::sockaddr_in = mem::zeroed();
            sa.sin_len = mem::size_of::<libc::sockaddr_in>() as u8;
            sa.sin_family = libc::AF_INET as u8;
            sa.sin_addr.s_addr = u32::from_ne_bytes(v4.octets());
            push_struct(buf, sa);
        }
        IpAddr::V6(v6) => {
            let mut sa: libc::sockaddr_in6 = mem::zeroed();
            sa.sin6_len = mem::size_of::<libc::sockaddr_in6>() as u8;
            sa.sin6_family = libc::AF_INET6 as u8;
            sa.sin6_addr.s6_addr = v6.octets();
            push_struct(buf, sa);
        }
    }
}

// Prefix length for an exact host match (32 for IPv4, 128 for IPv6).
fn exact_prefixlen(addr: IpAddr) -> u8 {
    if addr.is_ipv4() {
        32
    } else {
        128
    }
}

// Total size of an SADB address extension (header + padded sockaddr), in bytes.
fn addr_ext_size(addr: IpAddr) -> usize {
    let sockaddr_size = match addr {
        IpAddr::V4(_) => mem::size_of::<libc::sockaddr_in>(),
        IpAddr::V6(_) => mem::size_of::<libc::sockaddr_in6>(),
    };
    mem::size_of::<SadbAddress>() + pfkey_align8(sockaddr_size)
}

// Append SA identity + src/dst address selectors and patches
// the total length into the SadbMsg header at offset 4.
unsafe fn push_sa_and_addresses(buf: &mut Vec<u8>, src: IpAddr, dst: IpAddr) {
    push_struct(
        buf,
        SadbSa {
            len: pfkey_unit64(mem::size_of::<SadbSa>()),
            exttype: SADB_EXT_SA,
            spi: TCP_SIG_SPI.to_be(),
            replay: 0,
            state: SADB_SASTATE_MATURE,
            auth: SADB_X_AALG_TCP_MD5,
            encrypt: SADB_EALG_NONE,
            flags: SADB_X_EXT_CYCSEQ,
        },
    );
    push_struct(
        buf,
        SadbXSa2 {
            len: pfkey_unit64(mem::size_of::<SadbXSa2>()),
            exttype: SADB_X_EXT_SA2,
            mode: IPSEC_MODE_ANY,
            reserved1: 0,
            reserved2: 0,
            sequence: 0,
            reqid: 0,
        },
    );
    push_struct(
        buf,
        SadbAddress {
            len: pfkey_unit64(addr_ext_size(src)),
            exttype: SADB_EXT_ADDRESS_SRC,
            proto: IPSEC_ULPROTO_ANY,
            prefixlen: exact_prefixlen(src),
            reserved: 0,
        },
    );
    push_sockaddr(buf, src);
    push_struct(
        buf,
        SadbAddress {
            len: pfkey_unit64(addr_ext_size(dst)),
            exttype: SADB_EXT_ADDRESS_DST,
            proto: IPSEC_ULPROTO_ANY,
            prefixlen: exact_prefixlen(dst),
            reserved: 0,
        },
    );
    push_sockaddr(buf, dst);
    let total_units = pfkey_unit64(buf.len()).to_ne_bytes();
    buf[4..6].copy_from_slice(&total_units);
}

// Build SADB_ADD message: <base, key, SA, address(SD)> (RFC 2367 §3.1.3).
fn build_sadb_add_buf(src: IpAddr, dst: IpAddr, key: &[u8]) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    unsafe {
        push_struct(
            &mut buf,
            SadbMsg {
                version: PF_KEY_V2 as u8,
                msg_type: SADB_ADD,
                errno: 0,
                satype: SADB_X_SATYPE_TCPSIGNATURE,
                len: 0,
                reserved: 0,
                seq: 0,
                pid: libc::getpid() as u32,
            },
        );
        // Auth key header; raw key bytes follow immediately, padded to 8 bytes.
        let key_ext_size = pfkey_align8(mem::size_of::<SadbKey>() + key.len());
        push_struct(
            &mut buf,
            SadbKey {
                len: pfkey_unit64(key_ext_size),
                exttype: SADB_EXT_KEY_AUTH,
                bits: (key.len() * 8) as u16,
                reserved: 0,
            },
        );
        buf.extend_from_slice(key);
        pad_to_8(&mut buf);
        push_sa_and_addresses(&mut buf, src, dst);
    }
    buf
}

// Build SADB_DELETE message: <base, SA, address(SD)> (RFC 2367 section 3.1.4).
// No key extension needed: DELETE identifies the SA by SPI and address pair.
fn build_sadb_del_buf(src: IpAddr, dst: IpAddr) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    unsafe {
        push_struct(
            &mut buf,
            SadbMsg {
                version: PF_KEY_V2 as u8,
                msg_type: SADB_DELETE,
                errno: 0,
                satype: SADB_X_SATYPE_TCPSIGNATURE,
                len: 0,
                reserved: 0,
                seq: 0,
                pid: libc::getpid() as u32,
            },
        );
        push_sa_and_addresses(&mut buf, src, dst);
    }
    buf
}

// Get local address from a socket using getsockname.
fn get_local_addr(fd: RawFd) -> io::Result<IpAddr> {
    let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;

    let ret =
        unsafe { libc::getsockname(fd, addr_of_mut!(storage) as *mut libc::sockaddr, &mut len) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            let sa = addr_of!(storage) as *const libc::sockaddr_in;
            let octets = unsafe { (*sa).sin_addr.s_addr }.to_ne_bytes();
            Ok(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        libc::AF_INET6 => {
            let sa = addr_of!(storage) as *const libc::sockaddr_in6;
            let octets = unsafe { (*sa).sin6_addr.s6_addr };
            Ok(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unsupported address family",
        )),
    }
}

// Send an SADB message via a PF_KEY socket and read the kernel's reply.
fn sadb_send_one(sock: libc::c_int, buf: &[u8]) -> io::Result<()> {
    let ret = unsafe { libc::send(sock, buf.as_ptr() as *const libc::c_void, buf.len(), 0) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    // Read the reply into a buffer large enough to avoid truncation; RFC 2367
    // guarantees the reply starts with an sadb_msg header, and we only inspect
    // the errno field (byte 2) in that header.
    let mut reply = [0u8; 512];
    let recv_ret = unsafe {
        libc::recv(
            sock,
            reply.as_mut_ptr() as *mut libc::c_void,
            reply.len(),
            0,
        )
    };

    if recv_ret < mem::size_of::<SadbMsg>() as isize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SADB reply too short",
        ));
    }

    // Check errno field in reply header (byte 2 of SadbMsg)
    let errno = reply[2];
    if errno != 0 {
        return Err(io::Error::from_raw_os_error(errno as i32));
    }

    Ok(())
}

// Add an SA, replacing any existing one (DELETE then ADD, like BIRD).
fn sadb_add(src: IpAddr, dst: IpAddr, key: &[u8]) -> io::Result<()> {
    // PF_KEY is a kernel key management socket. Sending to it writes into the kernel SADB.
    let sock = unsafe { libc::socket(libc::PF_KEY, libc::SOCK_RAW, PF_KEY_V2) };
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }
    // Closure ensures sock is closed exactly once regardless of which path is taken.
    let result = (|| {
        // SADB entries persist across TCP connections and don't expire automatically.
        // Always DELETE first to remove any stale entry, then ADD the new one.
        // Ignore ESRCH (entry not found) from DELETE - it's expected on first connection.
        let del_buf = build_sadb_del_buf(src, dst);
        if let Err(e) = sadb_send_one(sock, &del_buf) {
            if e.raw_os_error() != Some(libc::ESRCH) {
                return Err(e);
            }
        }
        // Now ADD the new entry
        sadb_send_one(sock, &build_sadb_add_buf(src, dst, key))
    })();
    unsafe { libc::close(sock) };
    result
}

/// Set TCP MD5 signature key on a socket for the given peer address (RFC 2385).
///
/// On FreeBSD, keys are registered in the kernel SADB via PF_KEY, then the
/// socket is enabled for TCP MD5 with TCP_MD5SIG setsockopt.
pub fn apply_tcp_md5(fd: RawFd, peer_addr: IpAddr, key: &[u8]) -> io::Result<()> {
    if key.len() > TCP_MD5_MAXKEYLEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "MD5 key too long (max 80 bytes)",
        ));
    }

    // Get local address from the socket (required - FreeBSD doesn't accept 0.0.0.0)
    let local_addr = get_local_addr(fd)?;

    // Register the key in SADB in both directions.
    sadb_add(local_addr, peer_addr, key)?;
    sadb_add(peer_addr, local_addr, key)?;

    setsockopt(fd, libc::IPPROTO_TCP, libc::TCP_MD5SIG, 1i32)
}

// Delete a single SADB entry identified by src/dst address pair.
fn sadb_del(src: IpAddr, dst: IpAddr) -> io::Result<()> {
    let sock = unsafe { libc::socket(libc::PF_KEY, libc::SOCK_RAW, PF_KEY_V2) };
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }
    let result = sadb_send_one(sock, &build_sadb_del_buf(src, dst));
    unsafe { libc::close(sock) };
    result
}

/// Remove TCP MD5 SADB entries for the given peer address (RFC 2385).
///
/// Deletes both directions registered by apply_tcp_md5. ESRCH (entry not found)
/// is silently ignored since the entry may have already been removed.
pub fn remove_tcp_md5(fd: RawFd, peer_addr: IpAddr) -> io::Result<()> {
    let local_addr = get_local_addr(fd)?;
    for (src, dst) in [(local_addr, peer_addr), (peer_addr, local_addr)] {
        if let Err(e) = sadb_del(src, dst) {
            if e.raw_os_error() != Some(libc::ESRCH) {
                return Err(e);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::utils::getsockopt_int;
    use std::net::TcpListener;
    use std::os::unix::io::AsRawFd;
    use tokio::net::TcpSocket;

    #[test]
    fn test_pfkey_helpers() {
        assert_eq!(pfkey_align8(0), 0);
        assert_eq!(pfkey_align8(1), 8);
        assert_eq!(pfkey_align8(7), 8);
        assert_eq!(pfkey_align8(8), 8);
        assert_eq!(pfkey_align8(9), 16);

        assert_eq!(pfkey_unit64(8), 1);
        assert_eq!(pfkey_unit64(16), 2);
        assert_eq!(pfkey_unit64(24), 3);
    }

    #[test]
    fn test_build_sadb_add_buf() {
        let src: IpAddr = "127.0.0.1".parse().unwrap();
        let dst: IpAddr = "127.0.0.2".parse().unwrap();
        let key = b"bgpsecret"; // 9 bytes

        let buf = build_sadb_add_buf(src, dst, key);

        // Total must be 8-byte aligned
        assert_eq!(buf.len() % 8, 0);

        // SadbMsg.msg_type (byte 1) and .satype (byte 3)
        assert_eq!(buf[1], SADB_ADD);
        assert_eq!(buf[3], SADB_X_SATYPE_TCPSIGNATURE);

        // SadbMsg.len (bytes 4-5) must equal total length in 8-byte units
        let msg_len = u16::from_ne_bytes([buf[4], buf[5]]);
        assert_eq!(msg_len as usize, buf.len() / 8);

        // Key bytes start at offset 24: SadbMsg (16) + SadbKey header (8)
        assert_eq!(&buf[24..24 + key.len()], key);
    }

    #[test]
    fn test_build_sadb_del_buf() {
        let src: IpAddr = "127.0.0.1".parse().unwrap();
        let dst: IpAddr = "127.0.0.2".parse().unwrap();
        let key = b"bgpsecret";

        let buf = build_sadb_del_buf(src, dst);

        assert_eq!(buf.len() % 8, 0);
        assert_eq!(buf[1], SADB_DELETE);
        assert_eq!(buf[3], SADB_X_SATYPE_TCPSIGNATURE);
        let msg_len = u16::from_ne_bytes([buf[4], buf[5]]);
        assert_eq!(msg_len as usize, buf.len() / 8);

        // DELETE omits the key extension, so it must be smaller than ADD
        assert!(buf.len() < build_sadb_add_buf(src, dst, key).len());
    }

    #[test]
    fn test_exact_prefixlen() {
        assert_eq!(exact_prefixlen("1.2.3.4".parse().unwrap()), 32);
        assert_eq!(exact_prefixlen("::1".parse().unwrap()), 128);
    }

    #[test]
    fn test_addr_ext_size() {
        let v4: IpAddr = "1.2.3.4".parse().unwrap();
        let v6: IpAddr = "::1".parse().unwrap();
        assert_eq!(addr_ext_size(v4) % 8, 0);
        assert_eq!(addr_ext_size(v6) % 8, 0);
        assert!(addr_ext_size(v6) > addr_ext_size(v4));
    }

    #[test]
    fn test_build_sadb_add_buf_v6() {
        let src: IpAddr = "::1".parse().unwrap();
        let dst: IpAddr = "::2".parse().unwrap();
        let key = b"bgpsecret";

        let buf = build_sadb_add_buf(src, dst, key);

        assert_eq!(buf.len() % 8, 0);
        assert_eq!(buf[1], SADB_ADD);
        assert_eq!(buf[3], SADB_X_SATYPE_TCPSIGNATURE);
        let msg_len = u16::from_ne_bytes([buf[4], buf[5]]);
        assert_eq!(msg_len as usize, buf.len() / 8);
    }

    #[test]
    fn test_get_local_addr_v4() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = get_local_addr(listener.as_raw_fd()).unwrap();
        assert_eq!(addr, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[test]
    fn test_get_local_addr_v6() {
        let listener = TcpListener::bind("[::1]:0").unwrap();
        let addr = get_local_addr(listener.as_raw_fd()).unwrap();
        assert_eq!(addr, IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)));
    }

    #[test]
    fn test_apply_gtsm_v4() {
        for min_ttl in [255u8, 254] {
            let socket = TcpSocket::new_v4().unwrap();
            // Bind required on FreeBSD before setsockopt in some cases
            socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
            let fd = socket.as_raw_fd();
            apply_gtsm(fd, "127.0.0.1".parse().unwrap(), min_ttl).unwrap();
            assert_eq!(getsockopt_int(fd, libc::IPPROTO_IP, libc::IP_TTL), TTL_MAX);
            assert_eq!(
                getsockopt_int(fd, libc::IPPROTO_IP, IP_MINTTL),
                min_ttl as libc::c_int,
            );
        }
    }

    #[test]
    fn test_apply_gtsm_v6() {
        let socket = TcpSocket::new_v6().unwrap();
        socket.bind("[::1]:0".parse().unwrap()).unwrap();
        let fd = socket.as_raw_fd();
        // On FreeBSD, IPv6 GTSM only sets outgoing hops (no inbound filter).
        apply_gtsm(fd, "::1".parse().unwrap(), 254).unwrap();
        assert_eq!(
            getsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS),
            TTL_MAX,
        );
    }

    #[test]
    fn test_set_ttl_max() {
        let socket = TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let fd = socket.as_raw_fd();
        set_ttl_max(fd, "127.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(getsockopt_int(fd, libc::IPPROTO_IP, libc::IP_TTL), TTL_MAX);

        let socket = TcpSocket::new_v6().unwrap();
        socket.bind("[::1]:0".parse().unwrap()).unwrap();
        let fd = socket.as_raw_fd();
        set_ttl_max(fd, "::1".parse().unwrap()).unwrap();
        assert_eq!(
            getsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS),
            TTL_MAX,
        );
    }

    // Requires root: PF_KEY socket needs elevated privileges. Run with sudo.
    #[test]
    fn test_apply_tcp_md5_v4() {
        let socket = TcpSocket::new_v4().unwrap();
        let peer_addr: IpAddr = "127.0.0.1".parse().unwrap();
        let key = b"test-bgp-md5-key";
        let result = apply_tcp_md5(socket.as_raw_fd(), peer_addr, key);
        assert!(result.is_ok(), "apply_tcp_md5 failed: {:?}", result.err());
    }

    #[test]
    fn test_apply_tcp_md5_key_too_long() {
        let socket = TcpSocket::new_v4().unwrap();
        let peer_addr: IpAddr = "127.0.0.1".parse().unwrap();
        let key = vec![0u8; 81]; // exceeds TCP_MD5_MAXKEYLEN
        let result = apply_tcp_md5(socket.as_raw_fd(), peer_addr, &key);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }
}
