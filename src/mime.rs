//! SOAP with attachments, as AS4 carries a message: a `multipart/related`
//! whose root part is the SOAP 1.2 envelope and whose other parts are the
//! payloads, each named by its `Content-ID` (AS4 profile section 2.1.1,
//! RFC 2387). A Signal Message with nothing attached travels as the
//! envelope alone, `application/soap+xml`.
//!
//! Every part is written `binary`: the payload goes on the wire as it is,
//! between a boundary no payload from this process contains, and comes
//! back to the byte. A partner's parts are read the same way — the headers
//! to the blank line, the bytes to the next boundary — so what was sent is
//! what arrives.

use std::time::{SystemTime, UNIX_EPOCH};

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
    let boundary = boundary();
    let content_type = format!(
        "multipart/related; boundary=\"{boundary}\"; type=\"{SOAP_TYPE}\"; start=\"<{ROOT_CID}>\""
    );
    let mut body = Vec::with_capacity(envelope.len() + 256);
    part(&mut body, &boundary, ROOT_CID, &soap, envelope.as_bytes());
    for (cid, bytes) in attachments {
        part(&mut body, &boundary, cid, "application/octet-stream", bytes);
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    (content_type, body)
}

/// The envelope and the attachments a body carries, read by its
/// `Content-Type`.
///
/// # Errors
/// Where the body is neither an envelope nor a multipart, a part has no
/// end, or no part is the envelope.
pub fn unpack(content_type: &str, body: &[u8]) -> Result<(String, Attachments)> {
    let Some(boundary) = parameter(content_type, "boundary") else {
        if is_envelope(content_type) {
            return Ok((String::from_utf8_lossy(body).into_owned(), Vec::new()));
        }
        return Err(protocol_error(format!(
            "a body that is neither SOAP nor multipart/related: {content_type}"
        )));
    };
    let opener = format!("--{boundary}").into_bytes();
    let delimiter = format!("\r\n--{boundary}").into_bytes();
    let mut at = find(body, 0, &opener)
        .ok_or_else(|| protocol_error("a multipart with no part"))?
        + opener.len();
    let mut envelope = None;
    let mut attachments = Vec::new();
    while !body[at..].starts_with(b"--") {
        let start = at + usize::from(body[at..].starts_with(b"\r\n")) * 2;
        let head_end = find(body, start, b"\r\n\r\n")
            .ok_or_else(|| protocol_error("a part with no blank line after its headers"))?;
        let head = String::from_utf8_lossy(&body[start..head_end]);
        let content_start = head_end + 4;
        let end = find(body, content_start, &delimiter)
            .ok_or_else(|| protocol_error("a part that ends before its boundary"))?;
        let content = &body[content_start..end];
        let kind = header(&head, "Content-Type").unwrap_or_default();
        if envelope.is_none() && is_envelope(&kind) {
            envelope = Some(String::from_utf8_lossy(content).into_owned());
        } else {
            let cid = header(&head, "Content-ID").unwrap_or_default();
            attachments.push((cid.trim_matches(['<', '>']).to_string(), content.to_vec()));
        }
        at = end + delimiter.len();
    }
    let envelope =
        envelope.ok_or_else(|| protocol_error("a multipart with no SOAP envelope in it"))?;
    Ok((envelope, attachments))
}

/// One part: the boundary, its headers, a blank line, the bytes, and the
/// CRLF that belongs to the next boundary.
fn part(body: &mut Vec<u8>, boundary: &str, cid: &str, content_type: &str, bytes: &[u8]) {
    let head = format!(
        "--{boundary}\r\nContent-Type: {content_type}\r\n\
         Content-Transfer-Encoding: binary\r\nContent-ID: <{cid}>\r\n\r\n"
    );
    body.extend_from_slice(head.as_bytes());
    body.extend_from_slice(bytes);
    body.extend_from_slice(b"\r\n");
}

/// A boundary no payload from this process is written around.
fn boundary() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos());
    format!("=_xmip_{nanos:x}")
}

/// Whether `content_type` is one an envelope part is written in.
fn is_envelope(content_type: &str) -> bool {
    let media = content_type.split(';').next().unwrap_or("").trim();
    ENVELOPE_TYPES
        .iter()
        .any(|kind| media.eq_ignore_ascii_case(kind))
}

/// One parameter of a `Content-Type`, its quotes off.
#[must_use]
pub fn parameter(content_type: &str, name: &str) -> Option<String> {
    content_type.split(';').skip(1).find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        key.trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().trim_matches('"').to_string())
    })
}

/// One header of a part, however it was capitalised.
fn header(head: &str, name: &str) -> Option<String> {
    head.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().to_string())
    })
}

/// Where `needle` first occurs in `haystack` at or after `from`.
fn find(haystack: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    haystack
        .get(from..)?
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|at| at + from)
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
        assert_eq!(parameter(kind, "TYPE").as_deref(), Some("text/xml"));
        assert_eq!(parameter(kind, "start"), None);
    }
}
