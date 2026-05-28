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

use crate::bgp::msg_notification::{BgpError, UpdateMessageError};
use crate::bgp::utils::ParserError;
pub use conf::bgp::{default_afi_safis, Afi, AfiSafi, AfiSafiError, Safi};

impl From<AfiSafiError> for ParserError {
    fn from(_: AfiSafiError) -> Self {
        ParserError::BgpError {
            error: BgpError::UpdateMessageError(UpdateMessageError::OptionalAttributeError),
            data: Vec::new(),
        }
    }
}

/// Parse AFI/SAFI from BGP OPEN message multiprotocol capability.
/// Format: [AFI_HIGH, AFI_LOW, RESERVED, SAFI]
pub fn afi_safi_from_capability_bytes(val: &[u8]) -> Result<AfiSafi, ParserError> {
    if val.len() < 4 {
        return Err(ParserError::BgpError {
            error: BgpError::UpdateMessageError(UpdateMessageError::OptionalAttributeError),
            data: Vec::new(),
        });
    }

    let afi_bytes = [val[0], val[1]];
    let afi = Afi::try_from(u16::from_be_bytes(afi_bytes))?;
    let safi = Safi::try_from(val[3])?;

    Ok(AfiSafi::new(afi, safi))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_afi_safi_from_capability_bytes() {
        // IPv4 Unicast: AFI=1, SAFI=1
        let bytes = [0x00, 0x01, 0x00, 0x01];
        let afi_safi = afi_safi_from_capability_bytes(&bytes).unwrap();
        assert_eq!(afi_safi.afi, Afi::Ipv4);
        assert_eq!(afi_safi.safi, Safi::Unicast);

        // IPv6 Unicast: AFI=2, SAFI=1
        let bytes = [0x00, 0x02, 0x00, 0x01];
        let afi_safi = afi_safi_from_capability_bytes(&bytes).unwrap();
        assert_eq!(afi_safi.afi, Afi::Ipv6);
        assert_eq!(afi_safi.safi, Safi::Unicast);

        // Too short
        let bytes = [0x00, 0x01, 0x00];
        assert!(afi_safi_from_capability_bytes(&bytes).is_err());

        // Unknown AFI
        let bytes = [0x00, 0x99, 0x00, 0x01];
        assert!(afi_safi_from_capability_bytes(&bytes).is_err());

        // Unknown SAFI
        let bytes = [0x00, 0x01, 0x00, 0x99];
        assert!(afi_safi_from_capability_bytes(&bytes).is_err());

        // BGP-LS: AFI=16388 (0x4004), SAFI=71 (0x47)
        let bytes = [0x40, 0x04, 0x00, 0x47];
        let afi_safi = afi_safi_from_capability_bytes(&bytes).unwrap();
        assert_eq!(afi_safi.afi, Afi::LinkState);
        assert_eq!(afi_safi.safi, Safi::LinkState);
    }

    #[test]
    fn test_afi_safi_serde_roundtrip() {
        let cases = vec![
            AfiSafi::new(Afi::Ipv4, Safi::Unicast),
            AfiSafi::new(Afi::Ipv6, Safi::Unicast),
            AfiSafi::new(Afi::Ipv4, Safi::Multicast),
            AfiSafi::new(Afi::Ipv6, Safi::Multicast),
            AfiSafi::new(Afi::LinkState, Safi::LinkState),
            AfiSafi::new(Afi::LinkState, Safi::LinkStateVpn),
        ];
        for afi_safi in cases {
            let json = serde_json::to_string(&afi_safi).unwrap();
            let parsed: AfiSafi = serde_json::from_str(&json).unwrap();
            assert_eq!(afi_safi, parsed);
        }
    }
}
