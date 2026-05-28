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

pub(super) const TTL_MAX: libc::c_int = 255;

use std::io;
use std::mem;
use std::net::IpAddr;
use std::os::unix::io::RawFd;
use std::ptr::addr_of;
#[cfg(test)]
use std::ptr::addr_of_mut;

pub(super) fn setsockopt<T: Sized>(
    fd: RawFd,
    level: libc::c_int,
    opt: libc::c_int,
    val: T,
) -> io::Result<()> {
    let ret = unsafe {
        libc::setsockopt(
            fd,
            level,
            opt,
            addr_of!(val) as *const libc::c_void,
            mem::size_of_val(&val) as libc::socklen_t,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Set outgoing IP TTL to 255 on a socket without enforcing a minimum inbound TTL.
///
/// Used on the listener socket so that SYN-ACKs are sent with TTL=255, allowing
/// remote peers that set IP_MINTTL=255 before connect() to complete the TCP handshake.
pub fn set_ttl_max(fd: RawFd, addr: IpAddr) -> io::Result<()> {
    match addr {
        IpAddr::V4(_) => setsockopt(fd, libc::IPPROTO_IP, libc::IP_TTL, TTL_MAX),
        IpAddr::V6(_) => setsockopt(fd, libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS, TTL_MAX),
    }
}

/// Enable TCP keep-alive on a socket (RFC 8210 Section 7).
pub fn set_tcp_keepalive(fd: RawFd) -> io::Result<()> {
    setsockopt(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1 as libc::c_int)
}

#[cfg(test)]
pub(crate) fn getsockopt_int(fd: RawFd, level: libc::c_int, opt: libc::c_int) -> libc::c_int {
    let mut val: libc::c_int = 0;
    let mut len = mem::size_of_val(&val) as libc::socklen_t;
    unsafe {
        libc::getsockopt(
            fd,
            level,
            opt,
            addr_of_mut!(val) as *mut libc::c_void,
            &mut len,
        );
    }
    val
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::io::AsRawFd;
    use tokio::net::TcpSocket;

    #[test]
    fn test_setsockopt_roundtrip() {
        // Set IP_TTL and read it back to verify setsockopt/getsockopt work correctly.
        let socket = TcpSocket::new_v4().unwrap();
        let fd = socket.as_raw_fd();
        setsockopt(fd, libc::IPPROTO_IP, libc::IP_TTL, 128i32).unwrap();
        assert_eq!(getsockopt_int(fd, libc::IPPROTO_IP, libc::IP_TTL), 128);
    }
}
