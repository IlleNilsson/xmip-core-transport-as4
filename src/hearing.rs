//! What one POST a Party makes is heard as, as it is read: a new User
//! Message, which waits for its receive cycle's verdict; one seen before,
//! receipted again at once; or one refused — not AS4, not for this party,
//! not what the profile's check takes — answered its Error at once.

use std::net::SocketAddr;

use http::inbound::Heard;
use http::server;
use net::http::{Request, Response};
use transport::error::{Result, TransportError, protocol_error};

use crate::As4Transport;
use crate::envelope::UserMessage;
use crate::mime;
use crate::receipting::soap;
use crate::signal::{self, Signal};

/// A new message heard: the message, its origin, its payload, and what
/// the request said of its sender.
pub type Held = (UserMessage, String, Vec<u8>, server::Sender);

/// What one POST is heard as: a new message waiting for its verdict;
/// `None`, answered its Receipt again, for one seen before; or the error,
/// answered its Error.
pub type Hearing = Heard<Result<Option<Held>>>;

impl As4Transport {
    /// What one POST from `peer` is: a new message, which waits for its
    /// verdict, or what is answered at once — the Receipt again for one
    /// seen before, the Error, with the status that says why, for one
    /// refused.
    pub(crate) fn hear(&self, request: &Request, peer: SocketAddr) -> Hearing {
        let (message, bytes) = match self.unpack(request) {
            Ok(unpacked) => unpacked,
            Err(error) => return refused(None, signal::VALUE_NOT_RECOGNIZED, error),
        };
        if let Err(error) = self.admit(&message, &bytes) {
            let id = message.message_id;
            return refused(Some(&id), signal::POLICY_NONCOMPLIANCE, error);
        }
        if self.receipting.seen(&message.message_id) {
            return match self.receipting.receipt(&message) {
                Ok(receipt) => Heard::Answered(Ok(None), receipt),
                // This side could not sign; the Party sends again.
                Err(error) => Heard::Answered(Err(error), Response::new(500)),
            };
        }
        let origin = format!(
            "as4://{peer}{}?from={}&message-id={}&action={}",
            request.path, message.from, message.message_id, message.action
        );
        let sender = server::Sender::of(request, peer);
        Heard::Waiting(Ok(Some((message, origin, bytes, sender))))
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
        self.receipting.signer.verify(&envelope, &attachments)?;
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
    fn admit(&self, message: &UserMessage, payload: &[u8]) -> Result<()> {
        if message.to != self.template.from {
            return Err(protocol_error(format!(
                "a message for {}, and this party is {}",
                message.to, self.template.from
            )));
        }
        match &self.check {
            Some(check) => check(message, payload),
            None => Ok(()),
        }
    }
}

/// A message refused as it was read, with the Error that says why: `503`
/// and `EBMS:0004` where saying it again may succeed, `400` and `code`
/// where it will not.
fn refused(ref_to: Option<&str>, code: &str, error: TransportError) -> Hearing {
    let (status, code) = if error.retryable {
        (503, signal::OTHER)
    } else {
        (400, code)
    };
    let fault = Signal::error(ref_to, code, &error.message);
    Heard::Answered(Err(error), soap(status, &fault))
}
