//! Google's push service: a data message carrying the subscription's id and the ciphertext,
//! which the app decrypts and shows itself (`spec/push.md`, What reaches the phone).

use crate::apns::pem_body;
use crate::config::FcmConfig;
use crate::platform::{Outcome, Push};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::SystemRandom;
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use serde::Deserialize;
use serde_json::json;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";

#[derive(Deserialize)]
struct ServiceAccount {
    client_email: String,
    private_key: String,
    token_uri: String,
}

pub struct Fcm {
    config: FcmConfig,
    account: ServiceAccount,
    key: RsaKeyPair,
    token: Mutex<Option<(String, Instant)>>,
    client: reqwest::Client,
}

impl Fcm {
    pub fn new(config: FcmConfig, client: reqwest::Client) -> anyhow::Result<Self> {
        let account: ServiceAccount =
            serde_json::from_str(&std::fs::read_to_string(&config.service_account_path)?)?;
        let key = RsaKeyPair::from_pkcs8(&pem_body(&account.private_key)?)
            .map_err(|e| anyhow::anyhow!("the service account's key is not an RSA key: {e}"))?;
        Ok(Fcm {
            config,
            account,
            key,
            token: Mutex::new(None),
            client,
        })
    }

    pub fn serves(&self, app: &str) -> bool {
        app == self.config.project_id
    }

    async fn access_token(&self) -> anyhow::Result<String> {
        let mut held = self.token.lock().await;
        if let Some((token, until)) = held.as_ref()
            && Instant::now() < *until
        {
            return Ok(token.clone());
        }
        let now = chrono::Utc::now().timestamp();
        let encode = |value: &[u8]| URL_SAFE_NO_PAD.encode(value);
        let input = format!(
            "{}.{}",
            encode(br#"{"alg":"RS256","typ":"JWT"}"#),
            encode(
                json!({
                    "iss": self.account.client_email,
                    "scope": SCOPE,
                    "aud": self.account.token_uri,
                    "iat": now,
                    "exp": now + 3600,
                })
                .to_string()
                .as_bytes()
            ),
        );
        let mut signature = vec![0; self.key.public().modulus_len()];
        self.key
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                input.as_bytes(),
                &mut signature,
            )
            .map_err(|_| anyhow::anyhow!("signing a Google token request failed"))?;
        // The assertion is base64url and dots, which need no escaping in a form body.
        let body = format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={input}.{}",
            encode(&signature)
        );
        #[derive(Deserialize)]
        struct Granted {
            access_token: String,
            expires_in: u64,
        }
        let granted: Granted = self
            .client
            .post(&self.account.token_uri)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let until = Instant::now() + Duration::from_secs(granted.expires_in.saturating_sub(300));
        *held = Some((granted.access_token.clone(), until));
        Ok(granted.access_token)
    }

    pub async fn send(&self, device_token: &str, push: &Push<'_>) -> anyhow::Result<Outcome> {
        let mut android = json!({
            "priority": if push.urgent { "HIGH" } else { "NORMAL" },
            "ttl": format!("{}s", push.ttl.as_secs()),
        });
        if let Some(topic) = push.topic {
            android["collapse_key"] = json!(topic);
        }
        let message = json!({
            "message": {
                "token": device_token,
                "data": { "s": push.subscription, "c": URL_SAFE_NO_PAD.encode(push.ciphertext) },
                "android": android,
            }
        });
        let response = self
            .client
            .post(format!(
                "{}/v1/projects/{}/messages:send",
                self.config.url, self.config.project_id
            ))
            .bearer_auth(self.access_token().await?)
            .json(&message)
            .send()
            .await?;
        let status = response.status();
        if status.is_success() {
            return Ok(Outcome::Delivered);
        }
        let body = response.text().await.unwrap_or_default();
        match status.as_u16() {
            404 => Ok(Outcome::Gone),
            400 if body.contains("UNREGISTERED") || body.contains("registration token") => {
                Ok(Outcome::Gone)
            }
            429 | 500.. => Ok(Outcome::Busy),
            _ => anyhow::bail!(
                "FCM answered {status}: {}",
                body.chars().take(300).collect::<String>()
            ),
        }
    }
}
