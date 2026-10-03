//! What a Party is answered once a User Message's receive cycle has
//! ended, and which messages this party has already taken.
//!
//! A Receipt is the proof a Party keeps, so it is signed and written only
//! on [`Verdict::Accepted`], once the Stream is Xmip's (runtime-model
//! section 5), and the message id is remembered then — reception awareness
//! (AS4 section 3.2) delivers a message once, and a message whose cycle
//! did not accept it was never delivered. [`Verdict::Refused`] answers an
//! ebMS Error of severity `failure` (ebMS 3.0 Core section 6.7) —
//! `EBMS:0101` `FailedAuthentication` for a sender not identified,
//! `EBMS:0004` Other for one not permitted or content refused — with the
//! `4xx` that says why (`http::server::refused`), so the sending MSH takes
//! it as final and does not send again. [`Verdict::Failed`] answers `503`
//! with `EBMS:0004`: a transient failure the sending MSH retries, so the
//! Party keeps the message and sends it again. A message seen before is
//! receipted again at once and not handed up again.

use std::sync::{Arc, Mutex, PoisonError};

use http::server;
use net::http::Response;
use transport::error::Result;
use transport::{Refusal, Verdict};

use crate::envelope::UserMessage;
use crate::mime;
use crate::signal::{self, Signal};
use crate::signer::Signer;

/// How many message ids are remembered for reception awareness before the
/// oldest is forgotten.
const REMEMBERED: usize = 1024;

/// What the Error a failed cycle answers says.
const SEND_AGAIN: &str = "the message was not taken into custody; send it again";

/// What the Error a refused cycle answers says.
const REFUSED: &str = "the message was refused; do not send it again";

/// The signer Receipts are signed with and the message ids taken, shared
/// with every arrival's acknowledgement.
#[derive(Clone)]
pub struct Receipting {
    pub signer: Arc<dyn Signer>,
    seen: Arc<Mutex<Vec<String>>>,
}

impl Receipting {
    /// Signing with `signer`, nothing seen.
    pub fn new(signer: Arc<dyn Signer>) -> Self {
        Self {
            signer,
            seen: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Whether `message_id` was taken before.
    pub fn seen(&self, message_id: &str) -> bool {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .any(|id| id == message_id)
    }

    /// The answer `verdict` earns `message`: its signed Receipt, the id
    /// remembered, on acceptance; the final Error and the `4xx` that says
    /// why on refusal; `503` and `EBMS:0004` on failure.
    ///
    /// # Errors
    /// Where the Receipt could not be signed; nothing is remembered then.
    pub fn answer(&self, message: &UserMessage, verdict: Verdict) -> Result<Response> {
        let at = Some(message.message_id.as_str());
        match verdict {
            Verdict::Accepted => {
                let receipt = self.receipt(message)?;
                self.remember(&message.message_id);
                Ok(receipt)
            }
            Verdict::Refused(why) => Ok(soap(
                server::refused(why),
                &Signal::error(at, code(why), REFUSED),
            )),
            Verdict::Failed => Ok(soap(
                server::FAILED,
                &Signal::error(at, signal::OTHER, SEND_AGAIN),
            )),
        }
    }

    /// `message`'s signed Receipt, answered `200`.
    ///
    /// # Errors
    /// Where the Receipt could not be signed.
    pub fn receipt(&self, message: &UserMessage) -> Result<Response> {
        let receipt = self.signer.sign(Signal::receipt(message), &[])?;
        Ok(soap(200, &receipt))
    }

    fn remember(&self, message_id: &str) {
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        if seen.iter().any(|id| id == message_id) {
            return;
        }
        if seen.len() == REMEMBERED {
            seen.remove(0);
        }
        seen.push(message_id.to_string());
    }
}

/// The ebMS Error a refusal is answered with (ebMS 3.0 Core sections
/// 6.7.1 and 6.7.2): `EBMS:0101` `FailedAuthentication` where the sender
/// could not be identified, `EBMS:0004` Other where it is not permitted or
/// its content was refused — no code of the Core says either closer.
const fn code(why: Refusal) -> &'static str {
    match why {
        Refusal::Unidentified => signal::FAILED_AUTHENTICATION,
        Refusal::Forbidden | Refusal::Unacceptable => signal::OTHER,
    }
}

/// `envelope` as the answer with `status`.
pub fn soap(status: u16, envelope: &str) -> Response {
    let (content_type, body) = mime::pack(envelope, &[]);
    Response::new(status)
        .header("Content-Type", &content_type)
        .body(&body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::Unsigned;

    #[test]
    fn acceptance_receipts_and_remembers_and_failure_asks_for_it_again() {
        let receipting = Receipting::new(Arc::new(Unsigned));
        let message = UserMessage::new("Buyer", "Seller", "s", "a");
        let failed = receipting
            .answer(&message, Verdict::Failed)
            .expect("failed");
        assert_eq!(failed.status, 503);
        assert!(!receipting.seen(&message.message_id), "never delivered");
        let accepted = receipting
            .answer(&message, Verdict::Accepted)
            .expect("accepted");
        assert_eq!(accepted.status, 200);
        assert!(receipting.seen(&message.message_id));
    }

    #[test]
    fn refusal_answers_a_final_error_by_why_and_remembers_nothing() {
        let receipting = Receipting::new(Arc::new(Unsigned));
        let message = UserMessage::new("Buyer", "Seller", "s", "a");
        for (why, status, code) in [
            (Refusal::Unidentified, 401, signal::FAILED_AUTHENTICATION),
            (Refusal::Forbidden, 403, signal::OTHER),
            (Refusal::Unacceptable, 422, signal::OTHER),
        ] {
            let refused = receipting
                .answer(&message, Verdict::Refused(why))
                .expect("refused");
            assert_eq!(refused.status, status);
            let body = String::from_utf8_lossy(&refused.body);
            assert!(body.contains(&format!("errorCode=\"{code}\"")), "{body}");
            assert!(body.contains("severity=\"failure\""), "{body}");
        }
        assert!(!receipting.seen(&message.message_id), "never delivered");
    }
}
