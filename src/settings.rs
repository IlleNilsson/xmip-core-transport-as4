//! What an AS4 Location is configured with: the declaration
//! [`As4Transport`] reads its settings through (ADR-0064, amendment
//! 2026-09-26).

use transport::Configured;
use transport::error::Result;
use xcore::settings::{Applies, Fixed, Kind, Presence, Read, Setting, Settings};

use crate::As4Transport;
use crate::envelope::{TEST_ACTION, TEST_SERVICE};

impl Configured for As4Transport {
    /// The address is the partner's MSH a Send Location posts to, or the
    /// one a Receive Location listens at: `as4://host:port/msh`. The
    /// WS-Security certificate is the Location's credentials, not a setting.
    const SETTINGS: &'static Settings = &Settings {
        technology: env!("CARGO_PKG_NAME"),
        settings: &[
            Setting {
                name: "party_id",
                kind: Kind::Text,
                presence: Presence::Required,
                meaning: "This party's own id: the From of a sent User Message, the To a \
                          received one must carry.",
                applies: Applies::Both,
            },
            Setting {
                name: "partner_id",
                kind: Kind::Text,
                presence: Presence::Required,
                meaning: "The id of the party sent to, written as the User Message's To.",
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
            Setting {
                name: "timeout",
                kind: Kind::Duration,
                presence: Presence::Optional,
                meaning: "How long a partner that stops mid-message is waited on; unbounded \
                          when left out.",
                applies: Applies::Both,
            },
        ],
    };

    fn configured(address: &str, settings: &Read) -> Result<Self> {
        // Unsigned until the Location's credentials supply the certificate.
        let transport = Self::new(
            address,
            settings.text("party_id"),
            settings.optional_text("partner_id").unwrap_or_default(),
        );
        let transport = match (
            settings.optional_text("service"),
            settings.optional_text("action"),
        ) {
            (Some(service), Some(action)) => transport.under(service, action),
            _ => transport,
        };
        Ok(match settings.optional_duration("timeout") {
            Some(timeout) => transport.timing_out_after(timeout),
            None => transport,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xcore::settings::Given;

    #[test]
    fn as4_declares_its_settings_and_reads_through_them() {
        assert_eq!(As4Transport::SETTINGS.problems(), Vec::<String>::new());
        let text = |name: &str, value: &str| (name.to_string(), Given::Text(value.to_string()));
        let given = [
            text("party_id", "Buyer"),
            text("partner_id", "Seller"),
            text("action", "Submit"),
            text("timeout", "30s"),
        ];
        let sent =
            As4Transport::open("as4://partner:8080/msh", Applies::Send, &given).expect("built");
        let endpoint = net::Endpoint::parse_under(&sent.endpoint, &crate::SCHEMES).expect("read");
        assert_eq!(
            (endpoint.secure(), endpoint.address()),
            (false, "partner:8080".into())
        );
        let template = sent.template();
        assert_eq!(
            (template.from.as_str(), template.to.as_str()),
            ("Buyer", "Seller")
        );
        assert_eq!(template.service, TEST_SERVICE);
        assert_eq!(template.action, "Submit");
        assert_eq!(sent.timeout, Some(std::time::Duration::from_secs(30)));
        let Err(refused) = As4Transport::open("as4://0.0.0.0:8080/msh", Applies::Receive, &given)
        else {
            panic!("a Receive Location names no partner");
        };
        assert!(refused.message.contains("\"partner_id\""), "{refused}");
    }
}
