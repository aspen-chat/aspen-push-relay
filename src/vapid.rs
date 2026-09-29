//! Checking that a push comes from the deployment a subscription was made for (RFC 8292):
//! `Authorization: vapid t=<JWT>, k=<key>`, the JWT signed ES256 with that key.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
use serde::Deserialize;

/// The longest a token may be good for (RFC 8292).
const MAX_LIFETIME_SECONDS: i64 = 24 * 60 * 60;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VapidError {
    #[error("the Authorization header is not `vapid t=…, k=…`")]
    Malformed,
    #[error("the push is signed with another key than the subscription was made for")]
    WrongKey,
    #[error("the token's signature does not verify with the key it names")]
    Signature,
    #[error("the token is for {0}, not this relay")]
    Audience(String),
    #[error("the token has expired, or claims to last longer than a day")]
    Expiry,
}

#[derive(Deserialize)]
struct Header {
    alg: String,
}

#[derive(Deserialize)]
struct Claims {
    aud: String,
    exp: i64,
    sub: Option<String>,
}

/// What a verified token says of its sender.
#[derive(Debug, PartialEq, Eq)]
pub struct Sender {
    /// Its contact, when it gave one.
    pub subject: Option<String>,
}

/// Verifies `authorization` against the key a subscription was made for, for a relay at
/// `audience`, at `now` (seconds).
pub fn verify(
    authorization: &str,
    subscribed_key: &[u8],
    audience: &str,
    now: i64,
) -> Result<Sender, VapidError> {
    let rest = authorization
        .strip_prefix("vapid ")
        .ok_or(VapidError::Malformed)?;
    let mut token = None;
    let mut key = None;
    for part in rest.split(',') {
        match part.trim().split_once('=') {
            Some(("t", value)) => token = Some(value.trim()),
            Some(("k", value)) => key = Some(value.trim()),
            _ => {}
        }
    }
    let (Some(token), Some(key)) = (token, key) else {
        return Err(VapidError::Malformed);
    };
    let key = URL_SAFE_NO_PAD
        .decode(key.trim_end_matches('='))
        .map_err(|_| VapidError::Malformed)?;
    if key != subscribed_key {
        return Err(VapidError::WrongKey);
    }
    let (input, signature) = token.rsplit_once('.').ok_or(VapidError::Malformed)?;
    let (header, claims) = input.split_once('.').ok_or(VapidError::Malformed)?;
    let decode = |part: &str| {
        URL_SAFE_NO_PAD
            .decode(part)
            .map_err(|_| VapidError::Malformed)
    };
    let header: Header =
        serde_json::from_slice(&decode(header)?).map_err(|_| VapidError::Malformed)?;
    if header.alg != "ES256" {
        return Err(VapidError::Malformed);
    }
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &key)
        .verify(input.as_bytes(), &decode(signature)?)
        .map_err(|_| VapidError::Signature)?;
    let claims: Claims =
        serde_json::from_slice(&decode(claims)?).map_err(|_| VapidError::Malformed)?;
    if claims.aud.trim_end_matches('/') != audience.trim_end_matches('/') {
        return Err(VapidError::Audience(claims.aud));
    }
    if claims.exp <= now || claims.exp > now + MAX_LIFETIME_SECONDS {
        return Err(VapidError::Expiry);
    }
    Ok(Sender {
        subject: claims.sub,
    })
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

    /// A deployment's key, and the header it would send.
    pub fn signed(aud: &str, exp: i64) -> (Vec<u8>, String) {
        let rng = SystemRandom::new();
        let document =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, document.as_ref(), &rng)
                .unwrap();
        let encode = |value: &[u8]| URL_SAFE_NO_PAD.encode(value);
        let input = format!(
            "{}.{}",
            encode(br#"{"typ":"JWT","alg":"ES256"}"#),
            encode(
                format!(r#"{{"aud":"{aud}","exp":{exp},"sub":"https://chat.example"}}"#).as_bytes()
            )
        );
        let signature = pair.sign(&rng, input.as_bytes()).unwrap();
        let key = pair.public_key().as_ref().to_vec();
        let header = format!(
            "vapid t={input}.{}, k={}",
            encode(signature.as_ref()),
            encode(&key)
        );
        (key, header)
    }

    #[test]
    fn a_token_verifies_only_for_its_key_audience_and_lifetime() {
        let (key, header) = signed("https://push.example", 2_000);
        assert_eq!(
            verify(&header, &key, "https://push.example", 1_000),
            Ok(Sender {
                subject: Some("https://chat.example".into())
            })
        );
        assert_eq!(
            verify(&header, &[4; 65], "https://push.example", 1_000),
            Err(VapidError::WrongKey)
        );
        assert_eq!(
            verify(&header, &key, "https://other.example", 1_000),
            Err(VapidError::Audience("https://push.example".into()))
        );
        assert_eq!(
            verify(&header, &key, "https://push.example", 2_000),
            Err(VapidError::Expiry)
        );
        let (_, far) = signed("https://push.example", 1_000 + 2 * MAX_LIFETIME_SECONDS);
        let far_key = {
            let k = far.rsplit_once("k=").unwrap().1;
            URL_SAFE_NO_PAD.decode(k).unwrap()
        };
        assert_eq!(
            verify(&far, &far_key, "https://push.example", 1_000),
            Err(VapidError::Expiry)
        );
        let tampered = header.replacen("vapid t=ey", "vapid t=eZ", 1);
        assert!(verify(&tampered, &key, "https://push.example", 1_000).is_err());
        assert_eq!(
            verify("Bearer x", &key, "https://push.example", 1_000),
            Err(VapidError::Malformed)
        );
    }
}
