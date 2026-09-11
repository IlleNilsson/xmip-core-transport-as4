//! Who signs an AS4 message with WS-Security, and who does not.
//!
//! The AS4 profile signs the `eb:Messaging` header and every attachment
//! with an XML Signature inside a `wsse:Security` header, and the Receipt
//! carries the signed references back as non-repudiation. Both need a
//! certificate and a private key, which are the business of
//! `xmip-core-authenticate-certificate`, the dependency the manifest names:
//! it supplies a [`Signer`] and this crate applies it to every envelope.
//! Until it does, [`Unsigned`] leaves the envelope as it is, which is the
//! exchange two Xmip nodes on one wire agree on.

use transport::error::Result;

/// What signs an envelope on the way out and verifies it on the way in.
pub trait Signer: Send + Sync {
    /// `envelope` with its `wsse:Security` header, the `attachments` —
    /// each a content id and its bytes — referenced from the signature.
    ///
    /// # Errors
    /// Where the key or the certificate cannot sign.
    fn sign(&self, envelope: String, attachments: &[(String, Vec<u8>)]) -> Result<String>;

    /// `envelope` verified against its header and the attachments, the
    /// header left in place.
    ///
    /// # Errors
    /// Where the signature does not verify, or a signature was required
    /// and is not there.
    fn verify(&self, envelope: &str, attachments: &[(String, Vec<u8>)]) -> Result<()>;
}

/// No certificate: the envelope travels as it is.
#[derive(Clone, Copy, Debug, Default)]
pub struct Unsigned;

impl Signer for Unsigned {
    fn sign(&self, envelope: String, _attachments: &[(String, Vec<u8>)]) -> Result<String> {
        Ok(envelope)
    }

    fn verify(&self, _envelope: &str, _attachments: &[(String, Vec<u8>)]) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_unsigned_exchange_leaves_the_envelope_as_it_is() {
        let attachments = vec![("payload".to_string(), b"UNA".to_vec())];
        let signed = Unsigned
            .sign("<Envelope/>".to_string(), &attachments)
            .expect("signed");
        assert_eq!(signed, "<Envelope/>");
        assert!(Unsigned.verify(&signed, &attachments).is_ok());
    }
}
