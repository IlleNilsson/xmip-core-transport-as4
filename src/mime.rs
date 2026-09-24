//! SOAP with attachments, as AS4 carries a message: a `multipart/related`
//! whose root part is the SOAP 1.2 envelope and whose other parts are the
//! payloads, each named by its `Content-ID` (AS4 profile section 2.1.1,
//! RFC 2387). A Signal Message with nothing attached travels as the
//! envelope alone, `application/soap+xml`.
//!
//! The multipart body is `codec::mime`'s, written and read there for every
//! crate that carries MIME: every part `binary`, the payload on the wire as
//! it is between a boundary no payload from this process contains, and
//! back to the byte. What is AS4's here is which part is the envelope and
//! how the others are named.

use codec::mime::{self, Part};
use transport::error::{Result, protocol_error};

/// The media type of the envelope part.
pub const SOAP_TYPE: &str = "application/soap+xml";
/// The content id the envelope part carries.
pub const ROOT_CID: &str = "envelope@xmip";

/// The media types a partner may write the envelope part in.
const ENVELOPE_TYPES: [&str; 3] = [SOAP_TYPE, "text/xml", "application/xml"];

/// The parts beside the envelope: each a content id and its bytes.
pub type Attachments = Vec<(String, Vec<u8>)>;

/// `envelope` and `attachments` — each a content id and its bytes — as
/// one body, and the `Content-Type` that describes it.
#[must_use]
pub fn pack(envelope: &str, attachments: &[(String, Vec<u8>)]) -> (String, Vec<u8>) {
    let soap = format!("{SOAP_TYPE}; charset=utf-8");
    if attachments.is_empty() {
        return (soap, envelope.as_bytes().to_vec());
    }
    let boundary = mime::boundary();
    let content_type = format!(
        "multipart/related; boundary=\"{boundary}\"; type=\"{SOAP_TYPE}\"; start=\"<{ROOT_CID}>\""
    );
    let mut parts = vec![part(ROOT_CID, &soap, envelope.as_bytes())];
    for (cid, bytes) in attachments {
        parts.push(part(cid, "application/octet-stream", bytes));
    }
    (content_type, mime::write(&boundary, &parts))
}

/// The envelope and the attachments a body carries, read by its
/// `Content-Type`.
///
/// # Errors
/// Where the body is neither an envelope nor a multipart, a part has no
/// end, or no part is the envelope.
pub fn unpack(content_type: &str, body: &[u8]) -> Result<(String, Attachments)> {
    let Some(boundary) = mime::parameter(content_type, "boundary") else {
        if is_envelope(content_type) {
            return Ok((String::from_utf8_lossy(body).into_owned(), Vec::new()));
        }
        return Err(protocol_error(format!(
            "a body that is neither SOAP nor multipart/related: {content_type}"
        )));
    };
    let parts =
        mime::read(body, boundary).map_err(|refusal| protocol_error(refusal.to_string()))?;
    let mut envelope = None;
    let mut attachments = Vec::new();
    for part in parts {
        let kind = part.content_type().unwrap_or_default();
        if envelope.is_none() && is_envelope(kind) {
            envelope = Some(String::from_utf8_lossy(&part.body).into_owned());
        } else {
            let cid = part.content_id().unwrap_or_default().to_string();
            attachments.push((cid, part.body));
        }
    }
    let envelope =
        envelope.ok_or_else(|| protocol_error("a multipart with no SOAP envelope in it"))?;
    Ok((envelope, attachments))
}

/// One part: its type, written `binary`, and its content id.
fn part(cid: &str, content_type: &str, bytes: &[u8]) -> Part {
    Part::new(bytes)
        .header("Content-Type", content_type)
        .header("Content-Transfer-Encoding", "binary")
        .header("Content-ID", &format!("<{cid}>"))
}

/// Whether `content_type` is one an envelope part is written in.
fn is_envelope(content_type: &str) -> bool {
    let media = mime::media_type(content_type);
    ENVELOPE_TYPES.contains(&media.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_envelope_and_its_attachments_come_back_off_the_body_they_went_in() {
        let every: Vec<u8> = (0..=255).collect();
        let attachments = vec![
            ("payload@xmip".to_string(), every.clone()),
            ("empty@xmip".to_string(), Vec::new()),
            ("crlf@xmip".to_string(), b"\r\n--\r\n".to_vec()),
        ];
        let (content_type, body) = pack("<Envelope/>", &attachments);
        assert!(content_type.starts_with("multipart/related; boundary=\"=_xmip_"));
        assert!(body.ends_with(b"--\r\n"));
        let (envelope, back) = unpack(&content_type, &body).expect("unpacked");
        assert_eq!(envelope, "<Envelope/>");
        assert_eq!(back, attachments);
    }

    #[test]
    fn a_signal_travels_as_the_envelope_alone() {
        let (content_type, body) = pack("<Receipt/>", &[]);
        assert_eq!(content_type, "application/soap+xml; charset=utf-8");
        assert_eq!(body, b"<Receipt/>");
        let (envelope, back) = unpack(&content_type, &body).expect("unpacked");
        assert_eq!(envelope, "<Receipt/>");
        assert!(back.is_empty());
    }

    #[test]
    fn a_partner_body_is_read_as_it_was_written_and_a_hollow_one_refused() {
        let theirs = b"--b1\r\nContent-Type: text/xml\r\n\r\n<E/>\r\n\
            --b1\r\nContent-ID: <p1>\r\nContent-Type: application/octet-stream\r\n\r\nUNA\r\n\
            --b1--\r\n";
        let kind = "Multipart/Related; type=\"text/xml\"; boundary=b1";
        let (envelope, back) = unpack(kind, theirs).expect("unpacked");
        assert_eq!(envelope, "<E/>");
        assert_eq!(back, vec![("p1".to_string(), b"UNA".to_vec())]);
        assert!(unpack("text/plain", b"hello").is_err());
        assert!(unpack(kind, b"--b1\r\nContent-Type: text/xml\r\n\r\n<E/>").is_err());
        assert!(unpack(kind, b"--b1\r\nContent-ID: <p>\r\n\r\nx\r\n--b1--\r\n").is_err());
    }
}
