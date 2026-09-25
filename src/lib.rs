#![forbid(unsafe_code)]

//! Streams that arrive as AS4 User Messages. One User Message is one
//! Stream, its parties and its collaboration beside it.
//!
//! AS4 is the OASIS ebMS 3.0 profile for the exchange AS2 made ordinary,
//! done in SOAP: a POST whose body is a MIME `multipart/related`, a SOAP
//! 1.2 envelope as the root part with the `eb:Messaging` header naming
//! the parties, the service, the action and the payload, and the payload
//! as an attachment beside it by content id. The far end answers on the
//! same connection with a Signal Message: a Receipt naming the message it
//! took — the proof a partner keeps — or an Error saying why not. A Receive
//! Location answers partners; a Send Location posts to one and refuses the
//! send where the Receipt is missing, names another message, or is an
//! Error.
//!
//! Reception awareness (AS4 section 3.2) is the sender retrying until a
//! Receipt comes and the receiver never delivering one message twice: a
//! message id seen before is receipted again and not handed up again.
//!
//! WS-Security signing needs a certificate. The [`Signer`] is what
//! `xmip-core-authenticate-certificate` supplies, and without one the
//! exchange is [`Unsigned`] — two Xmip nodes on one wire, or a partner test
//! bench. A profile — Peppol is one — shapes the User Message it sends
//! through [`As4Transport::shaped`] and checks the one it takes through
//! [`As4Transport::checking`]. The http technology carries the request, the
//! answer and the endpoint; TLS is its `tls` feature (ADR-0033).
//!
//! The origin URI carries what the header knew:
//! `as4://peer/msh?from=Buyer&message-id=1.2@xmip&action=Submit`.

pub mod envelope;
mod loopback;
pub mod mime;
pub mod signal;
pub mod signer;

use std::net::TcpListener;
use std::sync::Mutex;
use std::time::Duration;

pub use envelope::UserMessage;
use net::Endpoint;
use net::http::{Request, Response, exchange, read_request, write_response};
pub use signal::Signal;
pub use signer::{Signer, Unsigned};
use transport::error::{Result, TransportError, protocol_error};
use transport::socket;
use transport::{Arrived, Directions, Transport};

/// What a message must satisfy beyond being addressed to this party — a
/// profile's own rules — checked before the Receipt is written.
pub type Check = Box<dyn Fn(&UserMessage) -> Result<()> + Send + Sync>;

/// How many message ids are remembered for reception awareness before the
/// oldest is forgotten.
const REMEMBERED: usize = 1024;

pub struct As4Transport {
    /// The partner's endpoint to send to, or the address to listen at.
    endpoint: String,
    /// The message every send is a fresh copy of; its `from` is this party.
    template: UserMessage,
    signer: Box<dyn Signer>,
    check: Option<Check>,
    timeout: Option<Duration>,
    seen: Mutex<Vec<String>>,
}

impl As4Transport {
    /// Speak as party `me` to `partner` at `endpoint` —
    /// `http://host:port/msh` or `as4://host:port/msh` — under the ebMS
    /// test service until [`Self::under`], unsigned until
    /// [`Self::signing_with`].
    #[must_use]
    pub fn new(endpoint: impl Into<String>, me: &str, partner: &str) -> Self {
        Self {
            endpoint: as_http(&endpoint.into()),
            template: UserMessage::new(me, partner, envelope::TEST_SERVICE, envelope::TEST_ACTION),
            signer: Box::new(Unsigned),
            check: None,
            timeout: None,
            seen: Mutex::new(Vec::new()),
        }
    }

    /// Send under `service` and `action`.
    #[must_use]
    pub fn under(mut self, service: &str, action: &str) -> Self {
        self.template.service = service.to_string();
        self.template.action = action.to_string();
        self
    }

    /// Send every message as a fresh copy of `template` — a profile's
    /// party types, agreement and properties.
    #[must_use]
    pub fn shaped(mut self, template: UserMessage) -> Self {
        self.template = template;
        self
    }

    /// Refuse, with an Error signal, any message `check` refuses.
    #[must_use]
    pub fn checking(
        mut self,
        check: impl Fn(&UserMessage) -> Result<()> + Send + Sync + 'static,
    ) -> Self {
        self.check = Some(Box::new(check));
        self
    }

    /// Sign with this, and verify with it.
    #[must_use]
    pub fn signing_with(mut self, signer: impl Signer + 'static) -> Self {
        self.signer = Box::new(signer);
        self
    }

    /// Give up on a partner that stops mid-message.
    #[must_use]
    pub const fn timing_out_after(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// The message every send is a copy of.
    #[must_use]
    pub const fn template(&self) -> &UserMessage {
        &self.template
    }

    /// Bind at the endpoint's authority as the far end partners post to,
    /// and report the address actually assigned.
    ///
    /// # Errors
    /// Where the address is taken, malformed, or not permitted.
    pub fn bind(&self) -> Result<(TcpListener, String)> {
        socket::bind_tcp(&Endpoint::parse(&self.endpoint)?.address())
    }

    /// Accept one message on an already-bound listener and answer its
    /// Receipt; `None` where it was one seen before, receipted again and
    /// not delivered again.
    ///
    /// # Errors
    /// Where the connection broke, the POST is not an AS4 message, or the
    /// message is refused — each answered with the Error that says so
    /// before the error is returned.
    pub fn accept_one(&self, listener: &TcpListener) -> Result<Option<(UserMessage, Arrived)>> {
        let (stream, peer) = socket::accept_tcp(listener, self.timeout)?;
        let (mut reader, mut writer) = socket::split(stream)?;
        let request = read_request(&mut reader)?
            .ok_or_else(|| protocol_error("a partner that connected and sent nothing"))?;
        let (ref_to, code, taken) = match self.unpack(&request) {
            Err(error) => (None, signal::VALUE_NOT_RECOGNIZED, Err(error)),
            Ok((message, bytes)) => {
                let id = Some(message.message_id.clone());
                match self.admit(&message) {
                    Ok(()) => (id, "", Ok((message, bytes))),
                    Err(error) => (id, signal::POLICY_NONCOMPLIANCE, Err(error)),
                }
            }
        };
        match taken {
            Ok((message, bytes)) => {
                let receipt = self.signer.sign(Signal::receipt(&message), &[])?;
                write_response(&mut writer, &soap(200, &receipt))?;
                if self.remember(&message.message_id) {
                    return Ok(None);
                }
                let origin = format!(
                    "as4://{peer}{}?from={}&message-id={}&action={}",
                    request.path, message.from, message.message_id, message.action
                );
                Ok(Some((message, Arrived::new(origin, bytes))))
            }
            Err(error) => {
                let (status, code) = if error.retryable {
                    (503, signal::OTHER)
                } else {
                    (400, code)
                };
                let fault = Signal::error(ref_to.as_deref(), code, &error.message);
                write_response(&mut writer, &soap(status, &fault))?;
                Err(error)
            }
        }
    }

    /// The User Message a request carries and its payload, the signature
    /// verified.
    fn unpack(&self, request: &Request) -> Result<(UserMessage, Vec<u8>)> {
        if request.method != "POST" {
            return Err(protocol_error(format!(
                "an AS4 message is a POST, not a {}",
                request.method
            )));
        }
        let content_type = request.header_value("Content-Type").unwrap_or_default();
        let (envelope, attachments) = mime::unpack(content_type, &request.body)?;
        self.signer.verify(&envelope, &attachments)?;
        let message = UserMessage::from_envelope(&envelope)?;
        let bytes = attachments
            .into_iter()
            .find(|(cid, _)| *cid == message.payload_cid)
            .map(|(_, bytes)| bytes)
            .ok_or_else(|| {
                protocol_error(format!(
                    "a message whose payload cid:{} is not attached",
                    message.payload_cid
                ))
            })?;
        Ok((message, bytes))
    }

    /// Whether this party takes `message`: addressed to it, and what the
    /// profile checks.
    fn admit(&self, message: &UserMessage) -> Result<()> {
        if message.to != self.template.from {
            return Err(protocol_error(format!(
                "a message for {}, and this party is {}",
                message.to, self.template.from
            )));
        }
        match &self.check {
            Some(check) => check(message),
            None => Ok(()),
        }
    }

    /// Whether `message_id` was seen before; remembered either way.
    fn remember(&self, message_id: &str) -> bool {
        let mut seen = self
            .seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if seen.iter().any(|id| id == message_id) {
            return true;
        }
        if seen.len() == REMEMBERED {
            seen.remove(0);
        }
        seen.push(message_id.to_string());
        false
    }

    /// Where a target names the partner's endpoint itself, or is empty and
    /// means the one configured.
    fn resolve(&self, target: &str) -> String {
        if target.is_empty() {
            self.endpoint.clone()
        } else {
            as_http(target)
        }
    }

    /// The Signal the partner answered, held against what was sent.
    fn verify_receipt(&self, response: &Response, sent: &UserMessage) -> Result<()> {
        let content_type = response.header_value("Content-Type").unwrap_or_default();
        let signal =
            mime::unpack(content_type, &response.body).and_then(|(envelope, attachments)| {
                self.signer.verify(&envelope, &attachments)?;
                Signal::from_envelope(&envelope)
            });
        if !(200..300).contains(&response.status) {
            let retryable = http::status::retryable(response.status);
            let why = match signal {
                Ok(Signal::Error {
                    code, description, ..
                }) => format!("{code}: {description}"),
                _ => String::from("no signal in the answer"),
            };
            return Err(TransportError {
                message: format!("the partner answered {} — {why}", response.status),
                retryable,
            });
        }
        match signal? {
            Signal::Receipt { ref_to, .. } if ref_to == sent.message_id => Ok(()),
            Signal::Receipt { ref_to, .. } => Err(protocol_error(format!(
                "a receipt for {ref_to}, not for {}",
                sent.message_id
            ))),
            Signal::Error {
                code, description, ..
            } => Err(protocol_error(format!(
                "the partner refused the message: {code}: {description}"
            ))),
        }
    }
}

/// `envelope` as the answer with `status`.
fn soap(status: u16, envelope: &str) -> Response {
    let (content_type, body) = mime::pack(envelope, &[]);
    Response::new(status)
        .header("Content-Type", &content_type)
        .body(&body)
}

/// `as4://` is `http://` on the wire, and `as4s://` is `https://`; any
/// other URL as it is. Public for the profiles that ride on AS4 and name
/// an access point in its scheme: Peppol.
#[must_use]
pub fn as_http(url: &str) -> String {
    if let Some(rest) = url.strip_prefix("as4://") {
        format!("http://{rest}")
    } else if let Some(rest) = url.strip_prefix("as4s://") {
        format!("https://{rest}")
    } else {
        url.to_string()
    }
}

impl Transport for As4Transport {
    fn name(&self) -> &'static str {
        "as4"
    }

    fn directions(&self) -> Directions {
        Directions::BOTH
    }

    fn receive(&self) -> Result<Vec<Arrived>> {
        let (listener, _) = self.bind()?;
        Ok(self
            .accept_one(&listener)?
            .map(|(_, arrived)| arrived)
            .into_iter()
            .collect())
    }

    fn send(&self, target: &str, bytes: &[u8]) -> Result<()> {
        let url = self.resolve(target);
        let endpoint = Endpoint::parse(&url)?;
        let message = self.template.fresh();
        let attachments = vec![(message.payload_cid.clone(), bytes.to_vec())];
        let envelope = self.signer.sign(message.envelope(), &attachments)?;
        let (content_type, body) = mime::pack(&envelope, &attachments);
        let request = Request::new("POST", endpoint.path())
            .header("Host", &endpoint.authority())
            .header("Content-Type", &content_type)
            .body(&body);
        let connection = http::endpoint::connect(&endpoint, self.timeout)?;
        let response = exchange(connection, &request)?;
        self.verify_receipt(&response, &message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn far_end() -> (As4Transport, TcpListener, String) {
        let far_end =
            As4Transport::new("as4://127.0.0.1:0/msh", "Seller", "Buyer").timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        (far_end, listener, address)
    }

    fn near(address: &str, me: &str, partner: &str) -> As4Transport {
        As4Transport::new(format!("as4://{address}/msh"), me, partner).timing_out_after(secs(2))
    }

    #[test]
    fn a_message_is_posted_and_its_receipt_names_it() {
        use transport::loopback::Loopback;
        let pair = As4Transport::loopback().under("urn:svc", "Submit");
        let first = pair.round(b"ISA*00*").expect("first");
        assert_eq!(first.bytes, b"ISA*00*");
        assert!(first.origin_uri.starts_with("as4://127.0.0.1:"));
        assert!(first.origin_uri.contains("/msh?from=Xmip&message-id="));
        assert!(first.origin_uri.ends_with("@xmip&action=Submit"));
        let long = vec![0x2a; 200_000];
        let second = pair.round(&long).expect("second");
        assert_eq!(second.bytes, long);
        let third = pair.round(b"").expect("third");
        assert!(third.bytes.is_empty());
        assert_eq!(pair.name(), "as4");
        assert_eq!(pair.directions(), Directions::BOTH);
        assert!(pair.claims().is_none());
    }

    #[test]
    fn a_message_seen_before_is_receipted_again_and_not_delivered_again() {
        let (far_end, listener, address) = far_end();
        let sender = std::thread::spawn(move || {
            let near = near(&address, "Buyer", "Seller");
            let message = near.template().fresh();
            let near = near.shaped(message);
            let attachments = vec![(envelope::PAYLOAD_CID.to_string(), b"once".to_vec())];
            let (content_type, body) = mime::pack(&near.template().envelope(), &attachments);
            for _ in 0..2 {
                let request = Request::new("POST", "/msh")
                    .header("Host", &address)
                    .header("Content-Type", &content_type)
                    .body(&body);
                let at = Endpoint::parse(&format!("http://{address}"))?;
                let connection = http::endpoint::connect(&at, Some(secs(2)))?;
                let response = exchange(connection, &request)?;
                near.verify_receipt(&response, near.template())?;
            }
            Ok::<(), TransportError>(())
        });
        let (_, first) = far_end.accept_one(&listener).expect("first").expect("new");
        assert_eq!(first.bytes, b"once");
        assert!(far_end.accept_one(&listener).expect("again").is_none());
        sender.join().expect("thread").expect("two receipts");
    }

    #[test]
    fn a_post_that_is_not_as4_is_answered_with_an_error_signal() {
        let (far_end, listener, address) = far_end();
        let poster = std::thread::spawn(move || {
            let mut stream = socket::connect_tcp(&address, Some(secs(2))).expect("connect");
            stream
                .write_all(b"POST /msh HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nISA")
                .expect("write");
            let mut answer = Vec::new();
            stream.read_to_end(&mut answer).expect("read");
            String::from_utf8_lossy(&answer).into_owned()
        });
        let error = far_end.accept_one(&listener).expect_err("not AS4");
        assert!(!error.retryable, "{error}");
        let answer = poster.join().expect("thread");
        assert!(answer.starts_with("HTTP/1.1 400"));
        assert!(answer.contains("errorCode=\"EBMS:0001\""), "{answer}");
    }

    #[test]
    fn a_message_for_another_party_or_against_the_profile_is_refused() {
        let (seller, listener, address) = far_end();
        let sender =
            std::thread::spawn(move || near(&address, "Buyer", "Somebody").send("", b"ISA"));
        assert!(seller.accept_one(&listener).is_err());
        let error = sender.join().expect("thread").expect_err("refused");
        assert!(!error.retryable);
        assert!(error.message.contains("EBMS:0103"), "{error}");
        let (seller, listener, address) = far_end();
        let strict = seller.checking(|message| {
            if message.action == "Submit" {
                Ok(())
            } else {
                Err(protocol_error("only Submit here"))
            }
        });
        let sender = std::thread::spawn(move || near(&address, "Buyer", "Seller").send("", b"ISA"));
        assert!(strict.accept_one(&listener).is_err());
        let error = sender.join().expect("thread").expect_err("refused");
        assert!(error.message.contains("only Submit here"), "{error}");
    }

    #[test]
    fn a_receipt_for_another_message_or_a_busy_partner_is_not_a_delivery() {
        let (_, listener, address) = far_end();
        std::thread::spawn(move || {
            let (stream, _) = socket::accept_tcp(&listener, Some(secs(2))).expect("accept");
            let (mut reader, mut writer) = socket::split(stream).expect("split");
            read_request(&mut reader).expect("read");
            let other = UserMessage::new("Buyer", "Seller", "s", "a");
            write_response(&mut writer, &soap(200, &Signal::receipt(&other))).expect("answered");
        });
        let error = near(&address, "Buyer", "Seller")
            .send("", b"ISA")
            .expect_err("wrong receipt");
        assert!(error.message.contains("a receipt for"), "{error}");
        assert!(!error.retryable);
        let (_, listener, address) = far_end();
        std::thread::spawn(move || {
            let (stream, _) = socket::accept_tcp(&listener, Some(secs(2))).expect("accept");
            let (mut reader, mut writer) = socket::split(stream).expect("split");
            read_request(&mut reader).expect("read");
            write_response(&mut writer, &Response::new(503)).expect("answered");
        });
        let error = near(&address, "Buyer", "Seller")
            .send("", b"ISA")
            .expect_err("busy");
        assert!(error.retryable, "{error}");
    }
}
