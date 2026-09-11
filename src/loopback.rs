//! AS4 at both ends on this machine: two Xmip nodes on one wire, unsigned
//! (ADR-0051). The far end is this party's MSH bound at an ephemeral port,
//! receipting the one message; the near end is this party again, posting to
//! it. Signing needs a certificate and a loopback has none, so the far end
//! is an [`Unsigned`] twin whatever the near end was given.

use std::net::TcpListener;
use std::sync::Mutex;

use http::target::HttpTarget;
use transport::error::{Result, protocol_error};
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
use transport::{Arrived, Transport};

use crate::{As4Transport, Unsigned, as_http};

/// The party both ends of a loopback are.
const PARTY: &str = "Xmip";

impl As4Transport {
    /// Both ends on this machine: an ephemeral local port, the loopback
    /// timeout, and one party — `Xmip` — sending to itself under the ebMS
    /// test service until [`Self::under`].
    #[must_use]
    pub fn loopback() -> Self {
        Self::new("as4://127.0.0.1:0/msh", PARTY, PARTY).timing_out_after(LOOPBACK_TIMEOUT)
    }

    /// This party at `endpoint`, unsigned, unchecked and with nothing seen:
    /// what each end of a loopback is.
    fn twin(&self, endpoint: String) -> Self {
        Self {
            endpoint,
            template: self.template.clone(),
            signer: Box::new(Unsigned),
            check: None,
            timeout: self.timeout,
            seen: Mutex::new(Vec::new()),
        }
    }
}

/// A bound MSH waiting for its one User Message, which it receipts.
struct Listening {
    transport: As4Transport,
    listener: TcpListener,
    address: String,
}

impl FarEnd for Listening {
    fn address(&self) -> &str {
        &self.address
    }

    fn take_one(self: Box<Self>) -> Result<Arrived> {
        self.transport
            .accept_one(&self.listener)?
            .map(|(_, arrived)| arrived)
            .ok_or_else(|| protocol_error("a message seen before: receipted, not delivered"))
    }
}

impl Loopback for As4Transport {
    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        let transport = self.twin(self.endpoint.clone());
        let (listener, address) = transport.bind()?;
        Ok(Box::new(Listening {
            transport,
            listener,
            address,
        }))
    }

    fn send_to(&self, address: &str, payload: &[u8]) -> Result<()> {
        let path = HttpTarget::parse(&self.endpoint)?.path;
        self.twin(as_http(&format!("as4://{address}{path}")))
            .send("", payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edge_payloads() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("empty", Vec::new()),
            ("one byte", vec![0x2a]),
            ("every byte", (0..=255).collect()),
            ("nul run", vec![0; 512]),
            ("high bytes", vec![0xff; 512]),
            ("crlf storm", b"\r\n".repeat(400)),
        ]
    }

    #[test]
    fn the_loopback_returns_the_edge_payloads_whole() {
        let pair = As4Transport::loopback();
        for (name, bytes) in edge_payloads() {
            let arrived = pair
                .round(&bytes)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(arrived.bytes, bytes, "{name}");
        }
        assert!(pair.ceiling().is_none());
        assert!(pair.refuses(b"\r\n\0").is_none());
        assert_eq!(pair.name(), "as4");
    }

    #[test]
    fn the_far_end_is_this_party_unsigned_and_receipts_what_it_takes() {
        let pair = As4Transport::loopback().under("urn:svc", "Submit");
        let arrived = pair.round(b"ISA*00*").expect("round");
        assert_eq!(arrived.bytes, b"ISA*00*");
        assert!(arrived.origin_uri.starts_with("as4://127.0.0.1:"));
        assert!(arrived.origin_uri.contains("/msh?from=Xmip&message-id="));
        assert!(arrived.origin_uri.ends_with("@xmip&action=Submit"));
        assert_eq!(pair.template().to, PARTY);
    }
}
