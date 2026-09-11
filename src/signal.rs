//! The Signal Message a receiver answers with: a Receipt naming the User
//! Message it took, or an Error saying why it did not (ebMS 3.0 Core
//! section 5.2.3, AS4 profile section 5.1.8).
//!
//! The Receipt of an unsigned exchange carries a copy of the User Message
//! it answers, which is what the profile says to send where there are no
//! signed references; the non-repudiation information a signed exchange
//! carries instead is the Signer's to add. An Error carries the ebMS code
//! and a description the sender can read in a log.

use transport::error::{Result, protocol_error};
use transport::xml::{escape, unescape};

use crate::envelope::{UserMessage, attribute, element, next_id, timestamp, wrap};

/// A body the receiver could not read as AS4.
pub const VALUE_NOT_RECOGNIZED: &str = "EBMS:0001";
/// A retryable failure on the receiver's side.
pub const OTHER: &str = "EBMS:0004";
/// A message that is AS4 and not one this party takes.
pub const POLICY_NONCOMPLIANCE: &str = "EBMS:0103";

/// What a receiver said about one message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signal {
    /// The message named was received.
    Receipt { ref_to: String, message_id: String },
    /// The message named — or none, where none could be read — was not.
    Error {
        ref_to: Option<String>,
        code: String,
        description: String,
    },
}

impl Signal {
    /// The envelope of a Receipt for `message`, its User Message copied
    /// in.
    #[must_use]
    pub fn receipt(message: &UserMessage) -> String {
        wrap(&format!(
            "<eb:SignalMessage>{}<eb:Receipt>{}</eb:Receipt></eb:SignalMessage>",
            info(Some(&message.message_id)),
            message.element()
        ))
    }

    /// The envelope of an Error `code` about `ref_to`, `description` for
    /// the sender's log.
    #[must_use]
    pub fn error(ref_to: Option<&str>, code: &str, description: &str) -> String {
        wrap(&format!(
            "<eb:SignalMessage>{}<eb:Error category=\"Content\" errorCode=\"{}\" \
             origin=\"ebMS\" severity=\"failure\"><eb:Description xml:lang=\"en\">{}\
             </eb:Description></eb:Error></eb:SignalMessage>",
            info(ref_to),
            escape(code),
            escape(description)
        ))
    }

    /// The Signal an envelope carries.
    ///
    /// # Errors
    /// Where the envelope has no `SignalMessage`, or one that is neither a
    /// Receipt naming a message nor an Error with a code.
    pub fn from_envelope(envelope: &str) -> Result<Self> {
        let signal = element(envelope, "SignalMessage")
            .ok_or_else(|| protocol_error("an answer with no SignalMessage in it"))?;
        let ref_to = element(signal, "RefToMessageId").map(unescape);
        if element(signal, "Receipt").is_some() {
            return Ok(Self::Receipt {
                ref_to: ref_to.ok_or_else(|| protocol_error("a Receipt naming no message"))?,
                message_id: element(signal, "MessageId")
                    .map(unescape)
                    .unwrap_or_default(),
            });
        }
        let code = attribute(signal, "Error", "errorCode")
            .ok_or_else(|| protocol_error("a SignalMessage that is neither Receipt nor Error"))?;
        Ok(Self::Error {
            ref_to,
            code,
            description: element(signal, "Description")
                .map(unescape)
                .unwrap_or_default(),
        })
    }
}

/// The `eb:MessageInfo` of a signal: now, a new id, and what it answers.
fn info(ref_to: Option<&str>) -> String {
    let reference = ref_to
        .map(|id| format!("<eb:RefToMessageId>{}</eb:RefToMessageId>", escape(id)))
        .unwrap_or_default();
    format!(
        "<eb:MessageInfo><eb:Timestamp>{}</eb:Timestamp><eb:MessageId>{}</eb:MessageId>\
         {reference}</eb:MessageInfo>",
        timestamp(),
        escape(&next_id())
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_receipt_names_the_message_it_answers_and_carries_a_copy_of_it() {
        let message = UserMessage::new("Buyer", "Seller", "urn:svc", "Submit");
        let envelope = Signal::receipt(&message);
        assert!(envelope.contains("<eb:Receipt><eb:UserMessage>"));
        match Signal::from_envelope(&envelope).expect("read") {
            Signal::Receipt { ref_to, message_id } => {
                assert_eq!(ref_to, message.message_id);
                assert_ne!(message_id, message.message_id);
                assert!(message_id.ends_with("@xmip"));
            }
            Signal::Error { .. } => panic!("a receipt"),
        }
    }

    #[test]
    fn an_error_carries_its_code_and_says_why() {
        let envelope = Signal::error(Some("1@them"), POLICY_NONCOMPLIANCE, "for <Somebody>");
        assert_eq!(
            Signal::from_envelope(&envelope).expect("read"),
            Signal::Error {
                ref_to: Some("1@them".to_string()),
                code: POLICY_NONCOMPLIANCE.to_string(),
                description: "for <Somebody>".to_string(),
            }
        );
        let unread = Signal::error(None, VALUE_NOT_RECOGNIZED, "not AS4");
        assert!(!unread.contains("RefToMessageId"));
        assert!(matches!(
            Signal::from_envelope(&unread),
            Ok(Signal::Error { ref_to: None, .. })
        ));
    }

    #[test]
    fn what_is_neither_receipt_nor_error_is_refused() {
        assert!(Signal::from_envelope(&wrap("")).is_err());
        assert!(
            Signal::from_envelope(&wrap(
                "<eb:SignalMessage><eb:PullRequest/></eb:SignalMessage>"
            ))
            .is_err()
        );
        let unnamed = wrap("<eb:SignalMessage><eb:Receipt>x</eb:Receipt></eb:SignalMessage>");
        assert!(Signal::from_envelope(&unnamed).is_err());
    }
}
