//! What the relay keeps: devices (one install of the app, with its platform token, and on iOS
//! the VoIP token calls are sent to),
//! subscriptions (a device's endpoint for one deployment key), each key's pushes this month, and
//! the tiers keys have been given.

use crate::database::Database;
use chrono::{DateTime, NaiveDate, Utc};
use diesel::prelude::*;
use diesel_async::pooled_connection::deadpool::Pool;
use diesel_async::{AsyncPgConnection, RunQueryDsl, SimpleAsyncConnection};
use uuid::Uuid;

pub type DbPool = Pool<AsyncPgConnection>;

diesel::table! {
    device (id) {
        id -> Uuid,
        secret_digest -> Bytea,
        platform -> Text,
        app -> Text,
        environment -> Text,
        token -> Text,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        voip_token -> Nullable<Text>,
    }
}

diesel::table! {
    subscription (id) {
        id -> Uuid,
        push_id -> Text,
        device -> Uuid,
        application_server_key -> Bytea,
        created_at -> Timestamptz,
        last_push_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    key_usage (application_server_key, month) {
        application_server_key -> Bytea,
        month -> Date,
        pushes -> Int8,
    }
}

diesel::table! {
    key_tier (application_server_key) {
        application_server_key -> Bytea,
        monthly_pushes -> Int8,
        note -> Text,
    }
}

diesel::joinable!(subscription -> device (device));
diesel::allow_tables_to_appear_in_same_query!(device, subscription, key_usage, key_tier);

/// The relay's schema, one step per entry, each applied once in order.
const MIGRATIONS: &[&str] = &[
    r#"
    CREATE TABLE device (
        id UUID PRIMARY KEY,
        secret_digest BYTEA NOT NULL,
        platform TEXT NOT NULL,
        app TEXT NOT NULL,
        environment TEXT NOT NULL,
        token TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE subscription (
        id UUID PRIMARY KEY,
        push_id TEXT NOT NULL UNIQUE,
        device UUID NOT NULL REFERENCES device (id) ON DELETE CASCADE,
        application_server_key BYTEA NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        last_push_at TIMESTAMPTZ
    );
    CREATE INDEX subscription_by_device ON subscription (device);
    CREATE TABLE key_usage (
        application_server_key BYTEA NOT NULL,
        month DATE NOT NULL,
        pushes BIGINT NOT NULL,
        PRIMARY KEY (application_server_key, month)
    );
    CREATE TABLE key_tier (
        application_server_key BYTEA PRIMARY KEY,
        monthly_pushes BIGINT NOT NULL,
        note TEXT NOT NULL DEFAULT ''
    );
"#,
    r#"
    ALTER TABLE device ADD COLUMN voip_token TEXT;
"#,
];

/// Connects as `database_url` says (`database`), and brings the schema up to date. Relays
/// starting together take turns.
pub async fn connect(database_url: &str) -> anyhow::Result<DbPool> {
    let database: Database = database_url.parse()?;
    let mut conn = database.connect().await?;
    conn.batch_execute(
        "SELECT pg_advisory_lock(7011);
         CREATE TABLE IF NOT EXISTS relay_migration (version INT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now());",
    )
    .await?;
    let applied: Vec<i32> = diesel::sql_query("SELECT version FROM relay_migration")
        .load::<Version>(&mut conn)
        .await?
        .into_iter()
        .map(|v| v.version)
        .collect();
    for (index, sql) in MIGRATIONS.iter().enumerate() {
        let version = i32::try_from(index + 1)?;
        if applied.contains(&version) {
            continue;
        }
        conn.batch_execute(&format!(
            "BEGIN; {sql} INSERT INTO relay_migration (version) VALUES ({version}); COMMIT;"
        ))
        .await?;
        tracing::info!(version, "applied a relay migration");
    }
    conn.batch_execute("SELECT pg_advisory_unlock(7011);")
        .await?;
    Ok(database.pool()?)
}

#[derive(QueryableByName)]
struct Version {
    #[diesel(sql_type = diesel::sql_types::Integer)]
    version: i32,
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = device)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Device {
    pub id: Uuid,
    pub secret_digest: Vec<u8>,
    pub platform: String,
    pub app: String,
    pub environment: String,
    pub token: String,
    /// PushKit's token, which a call is sent to; `None` for an Android device, and for an iOS
    /// app that registered none, which is then sent no calls.
    pub voip_token: Option<String>,
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = subscription)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Subscription {
    pub id: Uuid,
    pub application_server_key: Vec<u8>,
}

/// The first day of the month `now` is in, which usage is counted by.
pub fn month_of(now: DateTime<Utc>) -> NaiveDate {
    use chrono::Datelike;
    NaiveDate::from_ymd_opt(now.year(), now.month(), 1).expect("the first of a month exists")
}
