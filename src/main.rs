//! The Aspen push relay: the one holder of a published Aspen app's Apple and Google push
//! credentials, which wakes that app's phones for any Aspen deployment without learning what
//! it wakes them for. `spec/push.md` in the Aspen repository is the protocol.

mod api;
mod apns;
mod config;
mod db;
mod fcm;
mod platform;
mod usage;
mod vapid;

use std::sync::Arc;
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("RELAY_LOG")
                .unwrap_or_else(|_| "info".into()),
        )
        .init();
    let config = config::load()?;
    let db = db::connect(&config.database_url).await?;
    let client = reqwest::Client::builder()
        .user_agent(concat!("aspen-push-relay/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(15))
        .build()?;
    let apns = config
        .apns
        .clone()
        .map(|apns| apns::Apns::new(apns, client.clone()))
        .transpose()?;
    let fcm = config
        .fcm
        .clone()
        .map(|fcm| fcm::Fcm::new(fcm, client.clone()))
        .transpose()?;
    if apns.is_none() && fcm.is_none() {
        tracing::warn!("neither [apns] nor [fcm] is set: every device will be refused");
    }
    let listener = tokio::net::TcpListener::bind(config.listen_addr).await?;
    tracing::info!(addr = %config.listen_addr, public_url = config.public_url, "relay listening");
    let relay = Arc::new(api::Relay::new(config, db, apns, fcm));
    usage::spawn_flusher(relay.usage.clone(), relay.db.clone());
    axum::serve(listener, api::router(relay.clone()))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    // What was counted since the last save is saved before the relay goes.
    relay.usage.flush(&relay.db).await?;
    Ok(())
}
