//! Typed identifiers. All are lowercase `UUIDv4` on the wire.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use ts_rs::TS;
use uuid::Uuid;

macro_rules! id_type {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, TS)]
        #[serde(transparent)]
        #[ts(export, type = "string")]
        pub struct $name(pub Uuid);

        impl $name {
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.as_hyphenated().fmt(f)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0.as_hyphenated())
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(s).map(Self)
            }
        }
    };
}

id_type!(InstanceId);
id_type!(ProfileId);
id_type!(DnsProfileId);
id_type!(SecurityProfileId);
id_type!(TransportProfileId);
id_type!(GatewayId);
id_type!(AppId);
id_type!(ForwardBindingId);
id_type!(ProviderAccountId);
id_type!(SecretId);
id_type!(OperationId);
id_type!(SshHostId);
id_type!(BlocklistId);
id_type!(BanId);
id_type!(IpCheckId);
id_type!(InstallationId);
id_type!(SshDownloadJobId);
