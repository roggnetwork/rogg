// Copyright 2025 bgpgg Authors
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

use super::msg_notification::{BgpError, UpdateMessageError};
use super::msg_update_types::Nlri;
use crate::net::{IpNetwork, Ipv4Net, Ipv6Net};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::net::{Ipv4Addr, Ipv6Addr};

const MAX_IPV4_PREFIX_LEN: u8 = 32;
const MAX_IPV6_PREFIX_LEN: u8 = 128;
const PATH_ID_LEN: usize = 4;

/// Validate prefix length and calculate byte length for NLRI
fn validate_and_calculate_byte_len(
    prefix_length: u8,
    max_prefix_len: u8,
    remaining_bytes: usize,
) -> Result<usize, ParserError> {
    // Check prefix length before calculating byte_len
    if prefix_length > max_prefix_len {
        return Err(ParserError::BgpError {
            error: BgpError::UpdateMessageError(UpdateMessageError::InvalidNetworkField),
            data: Vec::new(),
        });
    }

    let byte_len: usize = (prefix_length as usize).div_ceil(8);

    if byte_len > remaining_bytes {
        return Err(ParserError::BgpError {
            error: BgpError::UpdateMessageError(UpdateMessageError::InvalidNetworkField),
            data: Vec::new(),
        });
    }

    Ok(byte_len)
}

#[derive(Debug, PartialEq)]
pub enum ParserError {
    IoError(String),
    BgpError {
        error: super::msg_notification::BgpError,
        data: Vec<u8>,
    },
}

impl Display for ParserError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            ParserError::IoError(s) => write!(f, "IO error: {}", s),
            ParserError::BgpError { error, .. } => write!(f, "BGP error: {:?}", error),
        }
    }
}

impl Error for ParserError {}

/// Parse optional 4-byte path identifier (RFC 7911).
fn parse_path_id(bytes: &[u8], add_path: bool) -> Result<Option<u32>, ParserError> {
    if !add_path {
        return Ok(None);
    }
    if bytes.len() < PATH_ID_LEN {
        return Err(ParserError::BgpError {
            error: BgpError::UpdateMessageError(UpdateMessageError::InvalidNetworkField),
            data: Vec::new(),
        });
    }
    Ok(Some(u32::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3],
    ])))
}

/// Parse IPv4 NLRI list. When add_path is true (RFC 7911), each entry is
/// preceded by a 4-byte path identifier.
pub fn parse_nlri_list(bytes: &[u8], add_path: bool) -> Result<Vec<Nlri>, ParserError> {
    let mut cursor = 0;
    let mut nlri_list = Vec::new();

    while cursor < bytes.len() {
        let path_id = parse_path_id(&bytes[cursor..], add_path)?;
        if path_id.is_some() {
            cursor += PATH_ID_LEN;
        }

        let prefix_length = bytes[cursor];
        cursor += 1;

        let byte_len = validate_and_calculate_byte_len(
            prefix_length,
            MAX_IPV4_PREFIX_LEN,
            bytes.len() - cursor,
        )?;

        let mut ip_buffer = [0; 4];
        ip_buffer[..byte_len].copy_from_slice(&bytes[cursor..(byte_len + cursor)]);

        let net = Ipv4Net {
            address: Ipv4Addr::from(ip_buffer),
            prefix_length,
        };

        // Semantic check: skip multicast prefixes (RFC 4271 Section 6.3)
        if net.is_multicast() {
            eprintln!("Warning: ignoring multicast NLRI prefix {:?}", net);
            cursor += byte_len;
            continue;
        }

        nlri_list.push(Nlri {
            prefix: IpNetwork::V4(net),
            path_id,
        });
        cursor += byte_len;
    }

    Ok(nlri_list)
}

/// Parse IPv6 NLRI list. When add_path is true (RFC 7911), each entry is
/// preceded by a 4-byte path identifier.
pub fn parse_nlri_v6_list(bytes: &[u8], add_path: bool) -> Result<Vec<Nlri>, ParserError> {
    let mut cursor = 0;
    let mut nlri_list = Vec::new();

    while cursor < bytes.len() {
        let path_id = parse_path_id(&bytes[cursor..], add_path)?;
        if path_id.is_some() {
            cursor += PATH_ID_LEN;
        }

        let prefix_length = bytes[cursor];
        cursor += 1;

        let byte_len = validate_and_calculate_byte_len(
            prefix_length,
            MAX_IPV6_PREFIX_LEN,
            bytes.len() - cursor,
        )?;

        let mut ip_buffer = [0; 16];
        ip_buffer[..byte_len].copy_from_slice(&bytes[cursor..(byte_len + cursor)]);

        let net = Ipv6Net {
            address: Ipv6Addr::from(ip_buffer),
            prefix_length,
        };

        nlri_list.push(Nlri {
            prefix: IpNetwork::V6(net),
            path_id,
        });
        cursor += byte_len;
    }

    Ok(nlri_list)
}

pub fn read_u32(bytes: &[u8]) -> Result<u32, ParserError> {
    match bytes.len() {
        4 => Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])),
        _ => Err(ParserError::BgpError {
            error: super::msg_notification::BgpError::UpdateMessageError(
                super::msg_notification::UpdateMessageError::AttributeLengthError,
            ),
            data: Vec::new(),
        }),
    }
}

/// Validates if an IPv4 address is a valid unicast host address.
/// Returns false for 0.0.0.0, 255.255.255.255, or multicast (224.0.0.0/4).
pub fn is_valid_unicast_ipv4(ip: u32) -> bool {
    !(ip == 0 || ip == 0xFFFFFFFF || (ip & 0xF0000000) == 0xE0000000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::msg_notification::{BgpError, UpdateMessageError};

    #[test]
    fn test_parse_nlri_list() {
        let test_cases = vec![
            // (description, input bytes, add_path, expected results)
            (
                "single prefix",
                vec![0x18, 0x0a, 0x0b, 0x0c],
                false,
                vec![Nlri {
                    prefix: IpNetwork::V4(Ipv4Net {
                        address: Ipv4Addr::new(10, 11, 12, 0),
                        prefix_length: 24,
                    }),
                    path_id: None,
                }],
            ),
            (
                "multiple prefixes",
                vec![
                    0x18, 0x0a, 0x0b, 0x0c, // 10.11.12.0/24
                    0x15, 0x0a, 0x0b, 0x08, // 10.11.8.0/21
                ],
                false,
                vec![
                    Nlri {
                        prefix: IpNetwork::V4(Ipv4Net {
                            address: Ipv4Addr::new(10, 11, 12, 0),
                            prefix_length: 24,
                        }),
                        path_id: None,
                    },
                    Nlri {
                        prefix: IpNetwork::V4(Ipv4Net {
                            address: Ipv4Addr::new(10, 11, 8, 0),
                            prefix_length: 21,
                        }),
                        path_id: None,
                    },
                ],
            ),
            (
                "multicast filtered",
                vec![
                    24, 10, 11, 12, // 10.11.12.0/24 - valid
                    24, 224, 0, 0, // 224.0.0.0/24 - multicast, filtered
                    24, 192, 168, 1, // 192.168.1.0/24 - valid
                ],
                false,
                vec![
                    Nlri {
                        prefix: IpNetwork::V4(Ipv4Net {
                            address: Ipv4Addr::new(10, 11, 12, 0),
                            prefix_length: 24,
                        }),
                        path_id: None,
                    },
                    Nlri {
                        prefix: IpNetwork::V4(Ipv4Net {
                            address: Ipv4Addr::new(192, 168, 1, 0),
                            prefix_length: 24,
                        }),
                        path_id: None,
                    },
                ],
            ),
            (
                "add_path single",
                vec![
                    0x00, 0x00, 0x00, 0x01, // path_id = 1
                    0x18, 0x0a, 0x0b, 0x0c, // 10.11.12.0/24
                ],
                true,
                vec![Nlri {
                    prefix: IpNetwork::V4(Ipv4Net {
                        address: Ipv4Addr::new(10, 11, 12, 0),
                        prefix_length: 24,
                    }),
                    path_id: Some(1),
                }],
            ),
            (
                "add_path multiple",
                vec![
                    0x00, 0x00, 0x00, 0x01, // path_id = 1
                    0x18, 0x0a, 0x0b, 0x0c, // 10.11.12.0/24
                    0x00, 0x00, 0x00, 0x02, // path_id = 2
                    0x10, 0xc0, 0xa8, // 192.168.0.0/16
                ],
                true,
                vec![
                    Nlri {
                        prefix: IpNetwork::V4(Ipv4Net {
                            address: Ipv4Addr::new(10, 11, 12, 0),
                            prefix_length: 24,
                        }),
                        path_id: Some(1),
                    },
                    Nlri {
                        prefix: IpNetwork::V4(Ipv4Net {
                            address: Ipv4Addr::new(192, 168, 0, 0),
                            prefix_length: 16,
                        }),
                        path_id: Some(2),
                    },
                ],
            ),
            (
                "add_path multicast filtered",
                vec![
                    0x00, 0x00, 0x00, 0x01, // path_id = 1
                    24, 10, 11, 12, // 10.11.12.0/24 - valid
                    0x00, 0x00, 0x00, 0x02, // path_id = 2
                    24, 224, 0, 0, // 224.0.0.0/24 - multicast, filtered
                    0x00, 0x00, 0x00, 0x03, // path_id = 3
                    24, 192, 168, 1, // 192.168.1.0/24 - valid
                ],
                true,
                vec![
                    Nlri {
                        prefix: IpNetwork::V4(Ipv4Net {
                            address: Ipv4Addr::new(10, 11, 12, 0),
                            prefix_length: 24,
                        }),
                        path_id: Some(1),
                    },
                    Nlri {
                        prefix: IpNetwork::V4(Ipv4Net {
                            address: Ipv4Addr::new(192, 168, 1, 0),
                            prefix_length: 24,
                        }),
                        path_id: Some(3),
                    },
                ],
            ),
        ];

        for (name, data, add_path, expected) in test_cases {
            let result = parse_nlri_list(&data, add_path).unwrap();
            assert_eq!(result, expected, "failed: {}", name);
        }
    }

    #[test]
    fn test_parse_nlri_list_errors() {
        let test_cases: Vec<(&str, Vec<u8>, bool)> = vec![
            (
                "invalid prefix length",
                vec![33, 0x0a, 0x0b, 0x0c, 0x0d, 0x00],
                false,
            ),
            ("truncated prefix", vec![24, 0x0a, 0x0b], false),
            (
                "add_path invalid prefix length",
                vec![0, 0, 0, 1, 33, 0x0a, 0x0b, 0x0c, 0x0d, 0x00],
                true,
            ),
            (
                "add_path truncated prefix",
                vec![0, 0, 0, 1, 24, 0x0a, 0x0b],
                true,
            ),
            ("add_path truncated path_id", vec![0x00, 0x01], true),
        ];

        for (name, data, add_path) in test_cases {
            match parse_nlri_list(&data, add_path) {
                Err(ParserError::BgpError { error, .. }) => {
                    assert_eq!(
                        error,
                        BgpError::UpdateMessageError(UpdateMessageError::InvalidNetworkField),
                        "wrong error for: {}",
                        name,
                    );
                }
                other => panic!("expected InvalidNetworkField for {}, got {:?}", name, other),
            }
        }
    }

    #[test]
    fn test_ipv4net_is_multicast() {
        let multicast = Ipv4Net {
            address: Ipv4Addr::new(224, 0, 0, 1),
            prefix_length: 24,
        };
        assert!(multicast.is_multicast());

        let unicast = Ipv4Net {
            address: Ipv4Addr::new(10, 0, 0, 0),
            prefix_length: 24,
        };
        assert!(!unicast.is_multicast());
    }

    #[test]
    fn test_is_valid_unicast_ipv4() {
        let test_cases = vec![
            (u32::from(Ipv4Addr::new(10, 0, 0, 1)), true, "10.0.0.1"),
            (
                u32::from(Ipv4Addr::new(192, 168, 1, 1)),
                true,
                "192.168.1.1",
            ),
            (u32::from(Ipv4Addr::new(1, 1, 1, 1)), true, "1.1.1.1"),
            (
                u32::from(Ipv4Addr::new(223, 255, 255, 255)),
                true,
                "223.255.255.255",
            ),
            (0x00000000, false, "0.0.0.0"),
            (0xFFFFFFFF, false, "255.255.255.255"),
            (0xE0000001, false, "224.0.0.1 (multicast)"),
            (0xEFFFFFFF, false, "239.255.255.255 (multicast)"),
        ];

        for (ip, expected, name) in test_cases {
            assert_eq!(is_valid_unicast_ipv4(ip), expected, "Failed for {}", name);
        }
    }

    #[test]
    fn test_parse_nlri_v6_list() {
        let test_cases = vec![
            (
                "single prefix",
                vec![0x20, 0x20, 0x01, 0x0d, 0xb8], // 2001:db8::/32
                false,
                vec![Nlri {
                    prefix: IpNetwork::V6(Ipv6Net {
                        address: Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0),
                        prefix_length: 32,
                    }),
                    path_id: None,
                }],
            ),
            (
                "multiple prefixes",
                vec![
                    0x20, 0x20, 0x01, 0x0d, 0xb8, // 2001:db8::/32
                    0x30, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, // 2001:db8:1::/48
                    0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01, // 2001:db8:0:1::/64
                    0x80, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x01, // 2001:db8::1/128
                ],
                false,
                vec![
                    Nlri {
                        prefix: IpNetwork::V6(Ipv6Net {
                            address: Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0),
                            prefix_length: 32,
                        }),
                        path_id: None,
                    },
                    Nlri {
                        prefix: IpNetwork::V6(Ipv6Net {
                            address: Ipv6Addr::new(0x2001, 0x0db8, 0x0001, 0, 0, 0, 0, 0),
                            prefix_length: 48,
                        }),
                        path_id: None,
                    },
                    Nlri {
                        prefix: IpNetwork::V6(Ipv6Net {
                            address: Ipv6Addr::new(0x2001, 0x0db8, 0, 1, 0, 0, 0, 0),
                            prefix_length: 64,
                        }),
                        path_id: None,
                    },
                    Nlri {
                        prefix: IpNetwork::V6(Ipv6Net {
                            address: Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1),
                            prefix_length: 128,
                        }),
                        path_id: None,
                    },
                ],
            ),
            ("empty", vec![], false, vec![]),
            (
                "add_path single",
                vec![
                    0x00, 0x00, 0x00, 0x05, // path_id = 5
                    0x20, 0x20, 0x01, 0x0d, 0xb8, // 2001:db8::/32
                ],
                true,
                vec![Nlri {
                    prefix: IpNetwork::V6(Ipv6Net {
                        address: Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0),
                        prefix_length: 32,
                    }),
                    path_id: Some(5),
                }],
            ),
            (
                "add_path multiple",
                vec![
                    0x00, 0x00, 0x00, 0x01, // path_id = 1
                    0x30, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, // 2001:db8:1::/48
                    0x00, 0x00, 0x00, 0x02, // path_id = 2
                    0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01, // 2001:db8:0:1::/64
                ],
                true,
                vec![
                    Nlri {
                        prefix: IpNetwork::V6(Ipv6Net {
                            address: Ipv6Addr::new(0x2001, 0x0db8, 0x0001, 0, 0, 0, 0, 0),
                            prefix_length: 48,
                        }),
                        path_id: Some(1),
                    },
                    Nlri {
                        prefix: IpNetwork::V6(Ipv6Net {
                            address: Ipv6Addr::new(0x2001, 0x0db8, 0, 1, 0, 0, 0, 0),
                            prefix_length: 64,
                        }),
                        path_id: Some(2),
                    },
                ],
            ),
        ];

        for (name, data, add_path, expected) in test_cases {
            let result = parse_nlri_v6_list(&data, add_path).unwrap();
            assert_eq!(result, expected, "failed: {}", name);
        }
    }

    #[test]
    fn test_parse_nlri_v6_list_errors() {
        let test_cases: Vec<(&str, Vec<u8>, bool)> = vec![
            ("invalid prefix length", vec![129, 0x20, 0x01], false),
            ("truncated prefix", vec![32, 0x20, 0x01], false),
            (
                "add_path invalid prefix length",
                vec![0, 0, 0, 1, 129, 0x20, 0x01],
                true,
            ),
            (
                "add_path truncated prefix",
                vec![0, 0, 0, 1, 32, 0x20, 0x01],
                true,
            ),
            ("add_path truncated path_id", vec![0x00, 0x01], true),
        ];

        for (name, data, add_path) in test_cases {
            match parse_nlri_v6_list(&data, add_path) {
                Err(ParserError::BgpError { error, .. }) => {
                    assert_eq!(
                        error,
                        BgpError::UpdateMessageError(UpdateMessageError::InvalidNetworkField),
                        "wrong error for: {}",
                        name,
                    );
                }
                other => panic!("expected InvalidNetworkField for {}, got {:?}", name, other),
            }
        }
    }
}
