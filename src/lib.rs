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
//! took — the proof a Party keeps — or an Error saying why not. A Receive
//! Location answers Parties; a Send Location posts to one and refuses the
//! send where the Receipt is missing, names another message, or is an
//! Error.
//!
//! Reception awareness (AS4 section 3.2) is the sender retrying until a
//! Receipt comes and the receiver never delivering one message twice: a
//! message id seen before is receipted again and not handed up again.
//!
//! WS-Security signing needs a certificate. The [`Signer`] is what
//! `xmip-core-authenticate-certificate` supplies, and without one the
//! exchange is [`Unsigned`] — two Xmip nodes on one wire, or a Party's test
//! bench. A profile — Peppol is one — shapes the User Message it sends
//! through [`As4Transport::shaped`] and checks the one it takes through
//! [`As4Transport::checking`]. The http technology carries the request, the
//! answer and the endpoint; TLS is its `tls` feature (ADR-0033).
//!
//! The origin URI carries what the header knew:
//! `as4://peer/msh?from=Buyer&message-id=1.2@xmip&action=Submit`.

pub mod envelope;
mod hearing;
mod loopback;
pub mod mime;
mod receipting;
mod settings;
pub mod signal;
pub mod signer;

use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

pub use envelope::UserMessage;
use http::endpoint::{Connections, Offer};
use http::inbound::{Heard, Inbound};
use http::server;
use net::http::{Request, Response};
use net::{Endpoint, Schemes};
pub use signal::Signal;
pub use signer::{Signer, Unsigned};
use transport::error::{Result, TransportError, protocol_error};
use transport::socket;
use transport::{Acknowledgement, Arrived, Directions, Taken, Transport, Verdict};

use crate::receipting::Receipting;

/// What a message and its payload must satisfy beyond being addressed to
/// this party — a profile's own rules — checked as the message is read,
/// and answered with an Error at once where they are not.
pub type Check = Box<dyn Fn(&UserMessage, &[u8]) -> Result<()> + Send + Sync>;

/// What one message taken off a Party's POST came to: the message and its
/// Stream, its Party waiting for the verdict, or `None` where it was one
/// seen before.
pub type Received = Result<Option<(UserMessage, Arrived)>>;

pub struct As4Transport {
    /// The Party's endpoint to send to, or the address to listen at.
    endpoint: String,
    /// The message every send is a fresh copy of; its `from` is this party.
    template: UserMessage,
    /// The signer, and the message ids taken.
    receipting: Receipting,
    check: Option<Check>,
    timeout: Option<Duration>,
    /// The connections kept to Parties' endpoints.
    connections: Connections,
    /// The listener a Receive Location keeps, and Parties' connections.
    inbound: Inbound,
}

impl As4Transport {
    /// Speak as Party `me` to Party `party` at `endpoint` —
    /// `http://host:port/msh` or `as4://host:port/msh` — under the ebMS
    /// test service until [`Self::under`], unsigned until
    /// [`Self::signing_with`].
    #[must_use]
    pub fn new(endpoint: impl Into<String>, me: &str, party: &str) -> Self {
        Self {
            endpoint: endpoint.into(),
            template: UserMessage::new(me, party, envelope::TEST_SERVICE, envelope::TEST_ACTION),
            receipting: Receipting::new(Arc::new(Unsigned)),
            check: None,
            timeout: None,
            connections: Connections::new(),
            inbound: Inbound::new(),
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

    /// Refuse, with an Error signal, any message whose header or payload
    /// `check` refuses.
    #[must_use]
    pub fn checking(
        mut self,
        check: impl Fn(&UserMessage, &[u8]) -> Result<()> + Send + Sync + 'static,
    ) -> Self {
        self.check = Some(Box::new(check));
        self
    }

    /// Sign with this, and verify with it.
    #[must_use]
    pub fn signing_with(mut self, signer: impl Signer + 'static) -> Self {
        self.receipting = Receipting::new(Arc::new(signer));
        self
    }

    /// Give up on a Party that stops mid-message.
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

    /// Bind at the endpoint's authority as the far end Parties post to,
    /// and report the address actually assigned.
    ///
    /// # Errors
    /// Where the address is taken, malformed, or not permitted.
    pub fn bind(&self) -> Result<(TcpListener, String)> {
        socket::bind_tcp(&Endpoint::parse_under(&self.endpoint, &SCHEMES)?.address())
    }

    /// Accept one message on an already-bound listener and answer its
    /// Receipt at once: what a far end does, which holds what it took
    /// whole. `None` where it was one seen before, receipted again and not
    /// delivered again.
    ///
    /// # Errors
    /// Where the connection broke, the POST is not an AS4 message, or the
    /// message is refused — each answered with the Error that says so
    /// before the error is returned.
    pub fn accept_one(&self, listener: &TcpListener) -> Result<Option<(UserMessage, Taken)>> {
        server::serve_one_from(listener, self.timeout, |request, peer| {
            let heard = match self.hear(request, peer) {
                Heard::Answered(said, answer) => return (said.map(|_| None), answer),
                Heard::Waiting(heard) => heard,
            };
            match heard {
                Ok(Some((message, origin, bytes, sender))) => {
                    match self.receipting.answer(&message, Verdict::Accepted) {
                        Ok(receipt) => {
                            let taken = sender.taken(Taken::new(origin, bytes));
                            (Ok(Some((message, taken))), receipt)
                        }
                        // This side could not sign; the Party sends again.
                        Err(error) => (Err(error), Response::new(500)),
                    }
                }
                other => (other.map(|_| None), Response::new(500)),
            }
        })?
    }

    /// The next message from whichever Party posts first, on the listener
    /// the first call bound and kept: what a Receive Location, and
    /// Peppol's access point, take. The Party waits for its answer until
    /// the arrival is given its verdict: its signed Receipt on
    /// [`Verdict::Accepted`]; a final ebMS Error and the `4xx` that says
    /// why on [`Verdict::Refused`], so the Party does not send it again;
    /// `503` and an ebMS Error `EBMS:0004` on [`Verdict::Failed`], so the
    /// Party sends it again (`receipting::Receipting::answer`). A message seen
    /// before is receipted again at once and is `None`; one refused is
    /// answered its Error at once and is the error.
    ///
    /// # Errors
    /// As [`Self::accept_one`], and where nothing arrived in time.
    pub fn take_next(&self) -> Received {
        let (heard, reply) = self.inbound.next(
            || self.bind(),
            self.timeout,
            |request, peer| self.hear(&request, peer),
        )?;
        let Some((message, origin, bytes, sender)) = heard? else {
            return Ok(None);
        };
        let reply = reply.ok_or_else(|| protocol_error("a message answered unheard"))?;
        let receipting = self.receipting.clone();
        let answered = message.clone();
        let acknowledgement = Acknowledgement::deferred(move |verdict| {
            // A Receipt that cannot be signed lets the Party go unanswered
            // — the dropped reply shuts its connection — and it resends.
            let answer = receipting.answer(&answered, verdict)?;
            reply.answer(&answer)
        });
        Ok(Some((
            message,
            sender.on(Arrived::whole(origin, bytes, acknowledgement)),
        )))
    }

    /// Bind the listener [`Self::take_next`] keeps now, where no receive
    /// has, and say where it is.
    ///
    /// # Errors
    /// Where the address is taken, malformed, or not permitted.
    pub fn listening(&self) -> Result<&str> {
        self.inbound.bound(|| self.bind())
    }

    /// Where a target names the Party's endpoint itself, or is empty and
    /// means the one configured.
    fn resolve<'a>(&'a self, target: &'a str) -> &'a str {
        if target.is_empty() {
            &self.endpoint
        } else {
            target
        }
    }

    /// The Signal the Party answered, held against what was sent.
    fn verify_receipt(&self, response: &Response, sent: &UserMessage) -> Result<()> {
        let content_type = response.header_value("Content-Type").unwrap_or_default();
        let signal =
            mime::unpack(content_type, &response.body).and_then(|(envelope, attachments)| {
                self.receipting.signer.verify(&envelope, &attachments)?;
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
                message: format!("the Party answered {} — {why}", response.status),
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
                "the Party refused the message: {code}: {description}"
            ))),
        }
    }
}

/// The schemes a Party's endpoint is written in: `as4://` is `http://`
/// on the wire, and `as4s://` is `https://`. Public for the profiles that
/// ride on AS4 and name an access point in its scheme: Peppol.
pub const SCHEMES: Schemes = Schemes {
    plain: &["http", "as4"],
    secure: &["https", "as4s"],
};

impl Transport for As4Transport {
    fn name(&self) -> &'static str {
        "as4"
    }

    fn directions(&self) -> Directions {
        Directions::BOTH
    }

    fn arrivals(&self) -> transport::Arrivals {
        transport::Arrivals::Unordered(
            "each request is its own, and a connection waiting for its answer takes no next request",
        )
    }

    /// The next message from whichever Party posts first, on the listener
    /// the first receive bound and the connections Parties keep; nothing
    /// where it was seen before. The Party waits for its Receipt until the
    /// verdict ([`Self::take_next`]).
    fn receive(&self) -> Result<Vec<Arrived>> {
        Ok(self
            .take_next()?
            .map(|(_, arrived)| arrived)
            .into_iter()
            .collect())
    }

    fn send(&self, target: &str, bytes: &[u8]) -> Result<()> {
        self.post(target, bytes, None)
    }

    /// The key is the User Message's `eb:MessageId`, `key@xmip`
    /// ([`envelope::message_id_of`]): a receiving MSH that has seen it
    /// receipts it again and does not deliver it again.
    fn send_keyed(&self, target: &str, bytes: &[u8], key: &str) -> Result<()> {
        self.post(target, bytes, Some(key))
    }
}

impl As4Transport {
    /// The one send: one User Message posted and its Receipt verified.
    fn post(&self, target: &str, bytes: &[u8], key: Option<&str>) -> Result<()> {
        let endpoint = Endpoint::parse_under(self.resolve(target), &SCHEMES)?;
        let message = self.template.fresh().keyed(key);
        let attachments = vec![(message.payload_cid.clone(), bytes.to_vec())];
        let envelope = self
            .receipting
            .signer
            .sign(message.envelope(), &attachments)?;
        let (content_type, body) = mime::pack(&envelope, &attachments);
        let request = Request::new("POST", endpoint.path())
            .header("Host", &endpoint.authority())
            .header("Content-Type", &content_type)
            .body(&body);
        let offer = Offer::Http11;
        let response = self
            .connections
            .exchange(&endpoint, self.timeout, offer, &request)?;
        self.verify_receipt(&response, &message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipting::soap;
    use net::http::{exchange, read_request, write_response};
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

    fn near(address: &str, me: &str, party: &str) -> As4Transport {
        As4Transport::new(format!("as4://{address}/msh"), me, party).timing_out_after(secs(2))
    }

    #[test]
    fn every_receive_takes_from_one_kept_listener_and_one_kept_connection() {
        let (seller, _, _) = far_end();
        let address = seller.listening().expect("bound").to_string();
        let buyer = std::thread::spawn(move || {
            let buyer = near(&address, "Buyer", "Seller");
            for round in 0..5u8 {
                buyer.send("", &[round]).expect("sent");
            }
            buyer.connections.opened()
        });
        for round in 0..5u8 {
            let mut arrived = seller.receive().expect("received");
            assert_eq!(arrived.remove(0).taken().expect("taken").bytes, [round]);
        }
        assert_eq!(
            buyer.join().expect("buyer"),
            1,
            "one connection for every send"
        );
        assert_eq!(seller.inbound.open(), 1);
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
    fn a_failed_cycle_answers_an_error_and_the_message_sent_again_is_taken() {
        let (seller, _, _) = far_end();
        let address = seller.listening().expect("bound").to_string();
        let sender = std::thread::spawn(move || {
            let near = near(&address, "Buyer", "Seller");
            let message = near.template().fresh();
            let near = near.shaped(message);
            let attachments = vec![(envelope::PAYLOAD_CID.to_string(), b"twice".to_vec())];
            let (content_type, body) = mime::pack(&near.template().envelope(), &attachments);
            let mut said = Vec::new();
            for _ in 0..3 {
                let request = Request::new("POST", "/msh")
                    .header("Host", &address)
                    .header("Content-Type", &content_type)
                    .body(&body);
                let at = Endpoint::parse(&format!("http://{address}"))?;
                let connection = http::endpoint::connect(&at, Some(secs(2)))?;
                let response = exchange(connection, &request)?;
                said.push(near.verify_receipt(&response, near.template()));
            }
            Ok::<_, TransportError>(said)
        });
        let (_, first) = seller.take_next().expect("first").expect("new");
        assert!(first.defers());
        assert!(!sender.is_finished(), "no Receipt before the verdict");
        first.failed().expect("failed");
        let (_, again) = seller
            .take_next()
            .expect("again")
            .expect("not seen: failed");
        assert_eq!(again.taken().expect("taken").bytes, b"twice");
        assert!(seller.take_next().expect("third").is_none(), "taken once");
        let said = sender.join().expect("thread").expect("exchanged");
        let refused = said[0].as_ref().expect_err("refused");
        assert!(refused.retryable, "{refused}");
        assert!(refused.message.contains("503"), "{refused}");
        assert!(refused.message.contains("EBMS:0004"), "{refused}");
        assert!(said[1].is_ok() && said[2].is_ok(), "{said:?}");
    }

    #[test]
    fn a_refused_cycle_answers_a_final_error_and_the_party_does_not_send_again() {
        let (seller, _, _) = far_end();
        let address = seller.listening().expect("bound").to_string();
        let buyer = std::thread::spawn(move || near(&address, "Buyer", "Seller").send("", b"no"));
        let (_, first) = seller.take_next().expect("first").expect("new");
        first
            .refused(transport::Refusal::Unidentified)
            .expect("refused");
        let refused = buyer.join().expect("buyer").expect_err("refused");
        assert!(!refused.retryable, "final: {refused}");
        assert!(refused.message.contains("401"), "{refused}");
        assert!(refused.message.contains("EBMS:0101"), "{refused}");
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
        let strict = seller.checking(|message, _| {
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
    fn a_receipt_for_another_message_or_a_busy_party_is_not_a_delivery() {
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
