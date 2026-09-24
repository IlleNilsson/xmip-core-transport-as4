//! The SOAP 1.2 envelope an AS4 User Message travels in: an `eb:Messaging`
//! header holding one `eb:UserMessage` — `MessageInfo`, `PartyInfo`,
//! `CollaborationInfo`, `PayloadInfo` — over an empty body, the payload
//! referenced by content id and carried as a MIME attachment beside it
//! (ebMS 3.0 Core section 5.2, AS4 profile section 2).
//!
//! Written by hand and read by scanning for local names, so a partner's
//! prefix — `eb:`, `eb3:`, `ns2:` — does not matter; what matters is the
//! element. The estate reads a protocol's flat XML that way (ADR-0044).

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use codec::civil::CivilTime;
use codec::xml::{escape, unescape};
use transport::error::{Result, protocol_error};

/// The ebMS 3.0 core namespace.
pub const EBMS: &str = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/";
/// The SOAP 1.2 envelope namespace.
pub const SOAP: &str = "http://www.w3.org/2003/05/soap-envelope";
/// The content id the payload attachment carries.
pub const PAYLOAD_CID: &str = "payload@xmip";
/// The service two MSHs exchange under until a P-Mode names one (ebMS 3.0
/// Core section 5.2.2.8).
pub const TEST_SERVICE: &str =
    "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/service";
/// The action that goes with [`TEST_SERVICE`].
pub const TEST_ACTION: &str = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/test";

const INITIATOR: &str = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/initiator";
const RESPONDER: &str = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/responder";

/// One User Message as its header describes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserMessage {
    pub message_id: String,
    pub timestamp: String,
    pub from: String,
    pub to: String,
    pub service: String,
    pub action: String,
    pub conversation_id: String,
    /// The content id of the payload part, without `cid:`.
    pub payload_cid: String,
    /// The `type` both party ids carry, where a profile gives them one.
    pub party_type: Option<String>,
    /// The `type` the service carries, where a profile gives it one.
    pub service_type: Option<String>,
    /// The agreement the exchange is under, where a profile names one.
    pub agreement: Option<String>,
    /// The message properties, name and value, in order.
    pub properties: Vec<(String, String)>,
    /// The payload part's properties, name and value, in order.
    pub payload_properties: Vec<(String, String)>,
}

impl UserMessage {
    /// A message from `from` to `to` under `service` and `action`, its
    /// payload in the attachment [`PAYLOAD_CID`].
    #[must_use]
    pub fn new(from: &str, to: &str, service: &str, action: &str) -> Self {
        let message_id = next_id();
        Self {
            conversation_id: message_id.clone(),
            message_id,
            timestamp: CivilTime::now().rfc3339(),
            from: from.to_string(),
            to: to.to_string(),
            service: service.to_string(),
            action: action.to_string(),
            payload_cid: PAYLOAD_CID.to_string(),
            party_type: None,
            service_type: None,
            agreement: None,
            properties: Vec::new(),
            payload_properties: vec![(
                "MimeType".to_string(),
                "application/octet-stream".to_string(),
            )],
        }
    }

    /// This message again as a new one: a new id, a new timestamp, a new
    /// conversation, everything else as it was — what a Send Location
    /// does with the message it was configured with, per send.
    #[must_use]
    pub fn fresh(&self) -> Self {
        let message_id = next_id();
        Self {
            conversation_id: message_id.clone(),
            message_id,
            timestamp: CivilTime::now().rfc3339(),
            ..self.clone()
        }
    }

    /// The `eb:UserMessage` element alone, as the envelope and the Receipt
    /// both carry it.
    #[must_use]
    pub fn element(&self) -> String {
        let party_type = typed(self.party_type.as_deref());
        let agreement = self
            .agreement
            .as_deref()
            .map(|agreement| format!("<eb:AgreementRef>{}</eb:AgreementRef>", escape(agreement)))
            .unwrap_or_default();
        let properties = if self.properties.is_empty() {
            String::new()
        } else {
            format!(
                "<eb:MessageProperties>{}</eb:MessageProperties>",
                property_elements(&self.properties)
            )
        };
        let part_properties = if self.payload_properties.is_empty() {
            String::new()
        } else {
            format!(
                "<eb:PartProperties>{}</eb:PartProperties>",
                property_elements(&self.payload_properties)
            )
        };
        format!(
            "<eb:UserMessage><eb:MessageInfo><eb:Timestamp>{}</eb:Timestamp>\
             <eb:MessageId>{}</eb:MessageId></eb:MessageInfo>\
             <eb:PartyInfo><eb:From><eb:PartyId{party_type}>{}</eb:PartyId>\
             <eb:Role>{INITIATOR}</eb:Role></eb:From><eb:To><eb:PartyId{party_type}>{}\
             </eb:PartyId><eb:Role>{RESPONDER}</eb:Role></eb:To></eb:PartyInfo>\
             <eb:CollaborationInfo>{agreement}<eb:Service{}>{}</eb:Service>\
             <eb:Action>{}</eb:Action><eb:ConversationId>{}</eb:ConversationId>\
             </eb:CollaborationInfo>{properties}<eb:PayloadInfo><eb:PartInfo href=\"cid:{}\">\
             {part_properties}</eb:PartInfo></eb:PayloadInfo></eb:UserMessage>",
            escape(&self.timestamp),
            escape(&self.message_id),
            escape(&self.from),
            escape(&self.to),
            typed(self.service_type.as_deref()),
            escape(&self.service),
            escape(&self.action),
            escape(&self.conversation_id),
            escape(&self.payload_cid),
        )
    }

    /// The whole envelope: the header with this message, an empty body.
    #[must_use]
    pub fn envelope(&self) -> String {
        wrap(&self.element())
    }

    /// The User Message an envelope carries.
    ///
    /// # Errors
    /// Where the envelope has no `UserMessage`, or one without its message
    /// id, parties or payload reference.
    pub fn from_envelope(envelope: &str) -> Result<Self> {
        let user = element(envelope, "UserMessage")
            .ok_or_else(|| protocol_error("an envelope with no UserMessage in it"))?;
        let required = |name: &str| {
            element(user, name)
                .map(unescape)
                .transpose()?
                .filter(|text| !text.is_empty())
                .ok_or_else(|| protocol_error(format!("a UserMessage with no {name}")))
        };
        let party = |side: &str| {
            element(user, side)
                .and_then(|party| element(party, "PartyId"))
                .map(unescape)
                .transpose()?
                .ok_or_else(|| protocol_error(format!("a UserMessage with no {side} party")))
        };
        let href = attribute(user, "PartInfo", "href")?
            .ok_or_else(|| protocol_error("a UserMessage with no payload reference"))?;
        Ok(Self {
            message_id: required("MessageId")?,
            timestamp: element(user, "Timestamp")
                .map(unescape)
                .transpose()?
                .unwrap_or_default(),
            from: party("From")?,
            to: party("To")?,
            service: required("Service")?,
            action: required("Action")?,
            conversation_id: element(user, "ConversationId")
                .map(unescape)
                .transpose()?
                .unwrap_or_default(),
            payload_cid: unescape(href.trim_start_matches("cid:"))?,
            party_type: match element(user, "From") {
                Some(from) => attribute(from, "PartyId", "type")?,
                None => None,
            },
            service_type: attribute(user, "Service", "type")?,
            agreement: element(user, "AgreementRef").map(unescape).transpose()?,
            properties: element(user, "MessageProperties")
                .map(properties)
                .transpose()?
                .unwrap_or_default(),
            payload_properties: element(user, "PartInfo")
                .map(properties)
                .transpose()?
                .unwrap_or_default(),
        })
    }
}

/// ` type="…"` where a type is given, nothing where none is.
fn typed(kind: Option<&str>) -> String {
    kind.map(|kind| format!(" type=\"{}\"", escape(kind)))
        .unwrap_or_default()
}

/// `properties` as `eb:Property` elements, in order.
fn property_elements(properties: &[(String, String)]) -> String {
    use std::fmt::Write;
    properties
        .iter()
        .fold(String::new(), |mut out, (name, value)| {
            let _ = write!(
                out,
                "<eb:Property name=\"{}\">{}</eb:Property>",
                escape(name),
                escape(value)
            );
            out
        })
}

/// Every `Property` element in `xml`, its `name` attribute and its text,
/// in order; one that is empty (`<x/>`) or unnamed is passed over.
///
/// # Errors
///
/// A name or text holds an entity XML does not define.
pub fn properties(xml: &str) -> Result<Vec<(String, String)>> {
    let mut found = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find('<') {
        let tag = &rest[start + 1..];
        let Some(end) = tag.find('>') else {
            break;
        };
        let open = &tag[..end];
        rest = &tag[end + 1..];
        if local_name(open) != "Property" || open.ends_with('/') {
            continue;
        }
        let Some(name) = value_of(open, "name")? else {
            continue;
        };
        let Some(close) = rest.find("</") else {
            break;
        };
        found.push((name, unescape(&rest[..close])?));
    }
    Ok(found)
}

/// The local name of the element `open` opens, whatever its prefix.
fn local_name(open: &str) -> &str {
    open.split([' ', '/'])
        .next()
        .and_then(|qualified| qualified.rsplit(':').next())
        .unwrap_or("")
}

/// The value of `attribute` in the open tag `open`, unescaped.
fn value_of(open: &str, attribute: &str) -> Result<Option<String>> {
    let key = format!("{attribute}=\"");
    let Some(at) = open.find(&key).map(|at| at + key.len()) else {
        return Ok(None);
    };
    let value = &open[at..];
    let Some(end) = value.find('"') else {
        return Ok(None);
    };
    Ok(Some(unescape(&value[..end])?))
}

/// `messaging` as the header of a SOAP 1.2 envelope with an empty body.
#[must_use]
pub fn wrap(messaging: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <S12:Envelope xmlns:S12=\"{SOAP}\" xmlns:eb=\"{EBMS}\"><S12:Header>\
         <eb:Messaging S12:mustUnderstand=\"true\">{messaging}</eb:Messaging>\
         </S12:Header><S12:Body/></S12:Envelope>"
    )
}

/// The content of the first element whose local name is `name`, whatever
/// its prefix, or `None` where there is none or it is empty (`<x/>`).
#[must_use]
pub fn element<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let mut rest = xml;
    while let Some(start) = rest.find('<') {
        let tag = &rest[start + 1..];
        let end = tag.find(['>', ' ', '/']).unwrap_or(tag.len());
        let local = tag[..end].rsplit(':').next().unwrap_or("");
        if local == name && !tag.starts_with('/') {
            let close = tag.find('>')?;
            if tag[..close].ends_with('/') {
                return None;
            }
            let content = &tag[close + 1..];
            let closing = content.find(&format!("{name}>"))?;
            let cut = content[..closing].rfind("</")?;
            return Some(&content[..cut]);
        }
        rest = &tag[end..];
    }
    None
}

/// The value of `attribute` on the first element whose local name is
/// `name`.
///
/// # Errors
///
/// The value holds an entity XML does not define.
pub fn attribute(xml: &str, name: &str, attribute: &str) -> Result<Option<String>> {
    let mut rest = xml;
    while let Some(start) = rest.find('<') {
        let tag = &rest[start + 1..];
        let Some(end) = tag.find('>') else {
            return Ok(None);
        };
        let open = &tag[..end];
        if local_name(open) == name {
            return value_of(open, attribute);
        }
        rest = &tag[end..];
    }
    Ok(None)
}

/// A message id no other message from this process carries.
pub(crate) fn next_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos());
    format!("{nanos}.{}@xmip", COUNTER.fetch_add(1, Ordering::Relaxed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_user_message_reads_back_off_the_envelope_it_wrote() {
        let message = UserMessage::new("Buyer & Co", "Seller", "urn:svc", "Submit");
        let envelope = message.envelope();
        assert!(envelope.contains("<eb:PartyId>Buyer &amp; Co</eb:PartyId>"));
        assert!(envelope.contains("href=\"cid:payload@xmip\""));
        assert_eq!(
            UserMessage::from_envelope(&envelope).expect("read"),
            message
        );
        assert!(message.timestamp.ends_with('Z'));
        assert_eq!(message.timestamp.len(), 20);
        assert_ne!(
            message.message_id,
            UserMessage::new("a", "b", "c", "d").message_id
        );
    }

    #[test]
    fn a_partner_prefix_does_not_matter_and_a_hollow_envelope_is_refused() {
        let theirs = "<S:Envelope xmlns:S=\"x\"><S:Header><ns2:Messaging><ns2:UserMessage>\
            <ns2:MessageInfo><ns2:MessageId>1@them</ns2:MessageId></ns2:MessageInfo>\
            <ns2:PartyInfo><ns2:From><ns2:PartyId type=\"urn:x\">A</ns2:PartyId></ns2:From>\
            <ns2:To><ns2:PartyId>B</ns2:PartyId></ns2:To></ns2:PartyInfo>\
            <ns2:CollaborationInfo><ns2:Service type=\"t\">s</ns2:Service><ns2:Action>a\
            </ns2:Action></ns2:CollaborationInfo><ns2:PayloadInfo><ns2:PartInfo \
            href=\"cid:p1\"/></ns2:PayloadInfo></ns2:UserMessage></ns2:Messaging>\
            </S:Header><S:Body/></S:Envelope>";
        let read = UserMessage::from_envelope(theirs).expect("read");
        assert_eq!(read.message_id, "1@them");
        assert_eq!(read.from, "A");
        assert_eq!(read.to, "B");
        assert_eq!(read.payload_cid, "p1");
        assert_eq!(read.conversation_id, "");
        assert!(UserMessage::from_envelope(&wrap("")).is_err());
        assert!(UserMessage::from_envelope("<eb:UserMessage/>").is_err());
        let no_href = theirs.replace(" href=\"cid:p1\"", "");
        assert!(UserMessage::from_envelope(&no_href).is_err());
    }

    #[test]
    fn an_element_is_found_by_local_name_and_an_empty_one_is_none() {
        assert_eq!(element("<a:X>1</a:X><Y>2</Y>", "X"), Some("1"));
        assert_eq!(element("<a:X>1</a:X><Y>2</Y>", "Y"), Some("2"));
        assert_eq!(element("<X/><X>late</X>", "X"), None);
        assert_eq!(element("<Xy>1</Xy>", "X"), None);
        assert_eq!(element("<X>never closed", "X"), None);
        assert_eq!(
            attribute("<a:P href=\"cid:q\"/>", "P", "href")
                .expect("read")
                .as_deref(),
            Some("cid:q")
        );
        assert_eq!(attribute("<P/>", "P", "href").expect("read"), None);
    }

    #[test]
    fn a_profile_shapes_the_message_and_reads_back_and_a_fresh_one_is_new() {
        let mut message = UserMessage::new("0088:1", "0088:2", "urn:proc", "urn:doc");
        message.party_type = Some("urn:fdc:peppol.eu:2017:identifiers:ap".to_string());
        message.service_type = Some("cenbii-procid-ubl".to_string());
        message.agreement = Some("urn:agreement".to_string());
        message.properties = vec![
            ("originalSender".to_string(), "0088:1".to_string()),
            ("finalRecipient".to_string(), "0088:2".to_string()),
        ];
        message.payload_properties.push((
            "CompressionType".to_string(),
            "application/gzip".to_string(),
        ));
        let envelope = message.envelope();
        assert!(envelope.contains("<eb:PartyId type=\"urn:fdc:peppol.eu:2017:identifiers:ap\">"));
        assert!(envelope.contains("<eb:Service type=\"cenbii-procid-ubl\">urn:proc</eb:Service>"));
        assert!(envelope.contains("<eb:Property name=\"finalRecipient\">0088:2</eb:Property>"));
        assert_eq!(
            UserMessage::from_envelope(&envelope).expect("read"),
            message
        );
        let again = message.fresh();
        assert_ne!(again.message_id, message.message_id);
        assert_eq!(again.conversation_id, again.message_id);
        assert_eq!(again.properties, message.properties);
        assert_eq!(
            properties("<p:Property name=\"a\">1</p:Property><Property/><Property name=\"b\"/>")
                .expect("read"),
            vec![("a".to_string(), "1".to_string())]
        );
    }
}
