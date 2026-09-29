//! `relay.toml`, with `RELAY_` environment variables overriding it (`__` between a section and
//! its keys: `RELAY_APNS__KEY_ID`; lists comma separated).

use serde::Deserialize;
use smart_default::SmartDefault;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    /// Where the relay listens, as plain HTTP; put a TLS proxy in front of it.
    #[serde(default = "default_listen_addr")]
    pub listen_addr: SocketAddr,
    /// The relay's public origin, such as `https://push.aspen.chat`: where its endpoints are,
    /// and the audience every deployment's VAPID token must name.
    pub public_url: String,
    pub database_url: String,
    /// Apple's push service, for the iOS app. Left out, iOS devices are refused.
    pub apns: Option<ApnsConfig>,
    /// Google's, for the Android app from the Play Store. Left out, Android devices are refused.
    pub fcm: Option<FcmConfig>,
    #[serde(default)]
    pub limits: LimitsConfig,
}

fn default_listen_addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8480))
}

#[derive(Clone, Debug, Deserialize)]
pub struct ApnsConfig {
    /// The Apple developer team the key belongs to.
    pub team_id: String,
    /// The key's id, as Apple shows it beside the key.
    pub key_id: String,
    /// The `.p8` file Apple gave for the key.
    pub key_path: PathBuf,
    /// The bundle ids of the apps this relay wakes; a device must name one.
    pub topics: Vec<String>,
    /// Whether the apps hold Apple's notification filtering entitlement, so their notification
    /// service extension may show nothing. Without it, a `low` urgency push (one that shows
    /// nothing) is accepted and not sent.
    #[serde(default)]
    pub filtering: bool,
    #[serde(default = "default_apns_production")]
    pub production_url: String,
    #[serde(default = "default_apns_sandbox")]
    pub sandbox_url: String,
}

fn default_apns_production() -> String {
    "https://api.push.apple.com".into()
}

fn default_apns_sandbox() -> String {
    "https://api.sandbox.push.apple.com".into()
}

#[derive(Clone, Debug, Deserialize)]
pub struct FcmConfig {
    /// The Firebase project the app belongs to; a device must name it.
    pub project_id: String,
    /// The service account's JSON key file, with the Firebase Cloud Messaging API Admin role.
    pub service_account_path: PathBuf,
    #[serde(default = "default_fcm")]
    pub url: String,
}

fn default_fcm() -> String {
    "https://fcm.googleapis.com".into()
}

#[derive(Clone, Debug, Deserialize, SmartDefault)]
#[serde(default)]
pub struct LimitsConfig {
    /// Pushes a deployment key may send each calendar month (UTC) without a tier of its own.
    #[default = 200_000]
    pub free_monthly_pushes: i64,
    /// Pushes one subscription may take back to back.
    #[default = 20]
    pub subscription_burst: u32,
    /// And then one every this many seconds.
    #[default = 3]
    pub subscription_interval_seconds: u64,
}

pub fn load() -> Result<Config, config::ConfigError> {
    let path = std::env::var("RELAY_CONFIG").unwrap_or_else(|_| "relay.toml".into());
    config::Config::builder()
        .add_source(config::File::new(&path, config::FileFormat::Toml).required(false))
        .add_source(
            config::Environment::with_prefix("RELAY")
                .prefix_separator("_")
                .separator("__")
                // `RELAY_APNS__TOPICS=org.aspen.chat,org.aspen.chat.beta`
                .list_separator(",")
                .with_list_parse_key("apns.topics")
                .try_parsing(true),
        )
        .build()?
        .try_deserialize()
}
