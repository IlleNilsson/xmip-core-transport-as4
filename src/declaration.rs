//! This technology's declaration: the transport guide's "The declaration",
//! `module/core/capability/transport/doc/adding-a-transport.md`. The ebMS
//! test service and action are the defaults of `service` and `action`, so
//! they are declared here, and the envelope a Send Location writes takes them
//! from here.

use xcore::settings::{Applies, Fixed, Kind, Presence, Setting, Settings};

/// The service two MSHs exchange under until a P-Mode names one (ebMS 3.0
/// Core section 5.2.2.8).
pub const TEST_SERVICE: &str =
    "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/service";
/// The action that goes with [`TEST_SERVICE`].
pub const TEST_ACTION: &str = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/test";

/// Every setting a Location takes beyond its address, the Party's MSH a
/// Send Location posts to, or the one a Receive Location listens at:
/// `as4://host:port/msh`. The WS-Security certificate is the Location's
/// credentials, not a setting.
pub const SETTINGS: &Settings = &Settings {
    technology: env!("CARGO_PKG_NAME"),
    settings: &[
        Setting {
            name: "party_id",
            kind: Kind::Text,
            presence: Presence::Required,
            meaning: "This Party's own id: the From of a sent User Message, the To a \
                      received one must carry.",
            applies: Applies::Both,
        },
        Setting {
            name: "to_party_id",
            kind: Kind::Text,
            presence: Presence::Required,
            meaning: "The id of the Party sent to, written as the User Message's To.",
            applies: Applies::Send,
        },
        Setting {
            name: "service",
            kind: Kind::Text,
            presence: Presence::Default(Fixed::Text(TEST_SERVICE)),
            meaning: "The ebMS service a User Message is sent under; the ebMS test \
                      service when left out.",
            applies: Applies::Send,
        },
        Setting {
            name: "action",
            kind: Kind::Text,
            presence: Presence::Default(Fixed::Text(TEST_ACTION)),
            meaning: "The ebMS action a User Message is sent under; the ebMS test \
                      action when left out.",
            applies: Applies::Send,
        },
        transport::configured::timeout(
            Applies::Both,
            None,
            "How long a Party that stops mid-message is waited on; unbounded \
             when left out.",
        ),
    ],
};

/// `as4://`, and `as4s://`, which TLS guards.
pub const SCHEMES: &[&str] = &["as4", "as4s"];
