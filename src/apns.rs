//! Apple's push service: an alert that Aspen's notification service extension replaces, carrying
//! the subscription's id and the ciphertext (`spec/push.md`, What reaches the phone).

use crate::config::ApnsConfig;
use crate::platform::{Outcome, Push};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use serde_json::json;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// How long a provider token is used; Apple takes one between twenty and sixty minutes old.
const TOKEN_REUSE: Duration = Duration::from_secs(40 * 60);
/// The key the app looks the placeholder up by in its strings.
pub const PLACEHOLDER_KEY: &str = "notification.placeholder";

pub struct Apns {
    config: ApnsConfig,
    key: EcdsaKeyPair,
    token: Mutex<Option<(String, Instant)>>,
    client: reqwest::Client,
}

impl Apns {
    pub fn new(config: ApnsConfig, client: reqwest::Client) -> anyhow::Result<Self> {
        let pem = std::fs::read_to_string(&config.key_path)?;
        let key = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            &pem_body(&pem)?,
            &SystemRandom::new(),
        )
        .map_err(|e| anyhow::anyhow!("the APNs key is not a P-256 PKCS #8 key: {e}"))?;
        Ok(Apns {
            config,
            key,
            token: Mutex::new(None),
            client,
        })
    }

    pub fn serves(&self, app: &str) -> bool {
        self.config.topics.iter().any(|topic| topic == app)
    }

    /// Whether the app may show nothing for a push, so that pushes that show nothing are sent.
    pub fn filtering(&self) -> bool {
        self.config.filtering
    }

    async fn provider_token(&self, fresh: bool) -> anyhow::Result<String> {
        let mut held = self.token.lock().await;
        if !fresh
            && let Some((token, made)) = held.as_ref()
            && made.elapsed() < TOKEN_REUSE
        {
            return Ok(token.clone());
        }
        let encode = |value: &[u8]| URL_SAFE_NO_PAD.encode(value);
        let input = format!(
            "{}.{}",
            encode(
                json!({"alg": "ES256", "kid": self.config.key_id})
                    .to_string()
                    .as_bytes()
            ),
            encode(
                json!({"iss": self.config.team_id, "iat": chrono::Utc::now().timestamp()})
                    .to_string()
                    .as_bytes()
            ),
        );
        let signature = self
            .key
            .sign(&SystemRandom::new(), input.as_bytes())
            .map_err(|_| anyhow::anyhow!("signing an APNs provider token failed"))?;
        let token = format!("{input}.{}", encode(signature.as_ref()));
        *held = Some((token.clone(), Instant::now()));
        Ok(token)
    }

    pub async fn send(
        &self,
        app: &str,
        environment: &str,
        device_token: &str,
        push: &Push<'_>,
    ) -> anyhow::Result<Outcome> {
        let base = if environment == "sandbox" {
            &self.config.sandbox_url
        } else {
            &self.config.production_url
        };
        let payload = json!({
            "aps": {
                "alert": { "loc-key": PLACEHOLDER_KEY },
                "mutable-content": 1,
                "sound": "default",
            },
            "aspen": { "s": push.subscription, "c": URL_SAFE_NO_PAD.encode(push.ciphertext) },
        });
        for fresh in [false, true] {
            let mut request = self
                .client
                .post(format!("{base}/3/device/{device_token}"))
                .bearer_auth(self.provider_token(fresh).await?)
                .header("apns-topic", app)
                .header("apns-push-type", "alert")
                .header("apns-priority", if push.urgent { "10" } else { "5" })
                .header(
                    "apns-expiration",
                    (chrono::Utc::now().timestamp() + push.ttl.as_secs() as i64).to_string(),
                )
                .json(&payload);
            if let Some(topic) = push.topic {
                request = request.header("apns-collapse-id", topic);
            }
            let response = request.send().await?;
            let status = response.status();
            if status.is_success() {
                return Ok(Outcome::Delivered);
            }
            let reason = response
                .json::<serde_json::Value>()
                .await
                .ok()
                .and_then(|body| body["reason"].as_str().map(String::from))
                .unwrap_or_default();
            match (status.as_u16(), reason.as_str()) {
                (410, _) | (400, "BadDeviceToken" | "DeviceTokenNotForTopic") => {
                    return Ok(Outcome::Gone);
                }
                // A provider token Apple thinks too old: make another and try once more.
                (403, "ExpiredProviderToken") if !fresh => continue,
                (429, _) | (500.., _) => return Ok(Outcome::Busy),
                _ => anyhow::bail!("APNs answered {status} {reason}"),
            }
        }
        anyhow::bail!("APNs refused a fresh provider token")
    }
}

/// The DER inside a PEM file.
pub fn pem_body(pem: &str) -> anyhow::Result<Vec<u8>> {
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .map(str::trim)
        .collect();
    Ok(STANDARD.decode(body)?)
}
