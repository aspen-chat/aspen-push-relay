//! The relay's API (`spec/push.md`, The relay's API): devices and their subscriptions for the
//! app, and the Web Push endpoint (RFC 8030) for deployments, which also take the one header
//! beyond Web Push's, `Aspen-Push-Kind: call`, naming a push that rings the phone.

use crate::apns::Apns;
use crate::config::Config;
use crate::db::{self, DbPool, Device, Subscription, device, subscription};
use crate::fcm::Fcm;
use crate::platform::{Outcome, Push};
use crate::usage::Usage;
use crate::vapid::{self, VapidError};
use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, patch, post};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use uuid::Uuid;

/// The largest message the relay takes: what fits, encoded, in an APNs payload with room for
/// the rest of it. RFC 8030 asks push services to take 4096 bytes; Aspen's pointers need far
/// less (`spec/push.md`).
pub const MAX_MESSAGE_BYTES: usize = 2048;
/// The longest a push waits for its phone.
const MAX_TTL: Duration = Duration::from_secs(4 * 7 * 24 * 60 * 60);
/// The longest a platform token is taken; APNs and FCM tokens are far shorter.
const MAX_TOKEN_CHARS: usize = 4096;
/// The header a deployment marks a call with (`spec/push.md`, Pushing), and its one value.
const KIND_HEADER: &str = "aspen-push-kind";
const KIND_CALL: &str = "call";

pub struct Relay {
    pub config: Config,
    pub db: DbPool,
    pub usage: Arc<Usage>,
    pub apns: Option<Apns>,
    pub fcm: Option<Fcm>,
    buckets: Mutex<HashMap<Uuid, (f64, Instant)>>,
}

impl Relay {
    pub fn new(config: Config, db: DbPool, apns: Option<Apns>, fcm: Option<Fcm>) -> Self {
        Relay {
            config,
            db,
            usage: Arc::new(Usage::default()),
            apns,
            fcm,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Takes one push from a subscription's budget, answering how long to wait when it is spent.
    fn take(&self, subscription: Uuid) -> Result<(), Duration> {
        let limits = &self.config.limits;
        let burst = f64::from(limits.subscription_burst);
        let interval = limits.subscription_interval_seconds.max(1) as f64;
        let now = Instant::now();
        let mut buckets = self
            .buckets
            .lock()
            .expect("the rate limiter is never poisoned");
        if buckets.len() > 100_000 {
            buckets.retain(|_, (_, at)| now.duration_since(*at).as_secs_f64() < burst * interval);
        }
        let (tokens, at) = buckets.entry(subscription).or_insert((burst, now));
        *tokens = (*tokens + now.duration_since(*at).as_secs_f64() / interval).min(burst);
        *at = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            Ok(())
        } else {
            Err(Duration::from_secs_f64((1.0 - *tokens) * interval))
        }
    }
}

type Shared = State<Arc<Relay>>;

pub fn router(relay: Arc<Relay>) -> axum::Router {
    axum::Router::new()
        .route("/v1/devices", post(create_device))
        .route(
            "/v1/devices/{device}",
            patch(update_device).delete(delete_device),
        )
        .route(
            "/v1/devices/{device}/subscriptions",
            post(create_subscription),
        )
        .route(
            "/v1/devices/{device}/subscriptions/{subscription}",
            delete(delete_subscription),
        )
        .route("/v1/push/{push_id}", post(push))
        .with_state(relay)
}

/// An RFC 9457 problem, as the Aspen API writes them: a stable `code`, and a `detail` saying
/// what to do.
pub struct Problem {
    status: StatusCode,
    code: &'static str,
    detail: String,
    retry_after: Option<Duration>,
}

impl Problem {
    fn new(status: StatusCode, code: &'static str, detail: impl Into<String>) -> Self {
        Problem {
            status,
            code,
            detail: detail.into(),
            retry_after: None,
        }
    }
}

impl IntoResponse for Problem {
    fn into_response(self) -> Response {
        let mut response = (
            self.status,
            [(header::CONTENT_TYPE, "application/problem+json")],
            json!({
                "type": "about:blank",
                "code": self.code,
                "title": self.status.canonical_reason().unwrap_or_default(),
                "status": self.status.as_u16(),
                "detail": self.detail,
            })
            .to_string(),
        )
            .into_response();
        if let Some(wait) = self.retry_after
            && let Ok(value) = HeaderValue::from_str(&wait.as_secs().max(1).to_string())
        {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
        response
    }
}

fn internal(error: impl std::fmt::Display) -> Problem {
    tracing::error!("{error}");
    Problem::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal",
        "Something failed on the relay. Try again later.",
    )
}

impl From<diesel::result::Error> for Problem {
    fn from(error: diesel::result::Error) -> Self {
        internal(error)
    }
}

impl From<diesel_async::pooled_connection::deadpool::PoolError> for Problem {
    fn from(error: diesel_async::pooled_connection::deadpool::PoolError) -> Self {
        internal(error)
    }
}

fn digest(secret: &str) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, secret.as_bytes())
        .as_ref()
        .to_vec()
}

fn random(bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    SystemRandom::new()
        .fill(&mut buffer)
        .expect("the system has randomness");
    URL_SAFE_NO_PAD.encode(buffer)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeviceRequest {
    platform: String,
    app: String,
    #[serde(default = "production")]
    environment: String,
    token: String,
    /// PushKit's token, for an `apns` device that can show calls.
    #[serde(default)]
    voip_token: Option<String>,
}

fn token_fits(token: &str) -> bool {
    !token.is_empty() && token.len() <= MAX_TOKEN_CHARS
}

/// Refuses a VoIP token on a device that is not Apple's: only PushKit issues one.
fn voip_token_allowed(platform: &str, voip_token: Option<&str>) -> Result<(), Problem> {
    match voip_token {
        Some(_) if platform != "apns" => Err(Problem::new(
            StatusCode::BAD_REQUEST,
            "validation",
            format!(
                "A voipToken belongs to an apns device alone; {platform} devices are sent calls through their one token."
            ),
        )),
        Some(token) if !token_fits(token) => Err(Problem::new(
            StatusCode::BAD_REQUEST,
            "validation",
            format!("A voipToken is at most {MAX_TOKEN_CHARS} characters, and not empty."),
        )),
        _ => Ok(()),
    }
}

fn production() -> String {
    "production".into()
}

#[derive(Serialize)]
struct DeviceCreated {
    device: Uuid,
    secret: String,
}

async fn create_device(
    State(relay): Shared,
    Json(request): Json<DeviceRequest>,
) -> Result<(StatusCode, Json<DeviceCreated>), Problem> {
    let served = match request.platform.as_str() {
        "apns" => relay
            .apns
            .as_ref()
            .is_some_and(|apns| apns.serves(&request.app)),
        "fcm" => relay
            .fcm
            .as_ref()
            .is_some_and(|fcm| fcm.serves(&request.app)),
        _ => false,
    };
    if !served {
        return Err(Problem::new(
            StatusCode::BAD_REQUEST,
            "unknownApp",
            format!(
                "This relay does not wake {} apps named {}. An app wakes its phones only through the relay of whoever published it.",
                request.platform, request.app
            ),
        ));
    }
    if !matches!(request.environment.as_str(), "production" | "sandbox")
        || !token_fits(&request.token)
    {
        return Err(Problem::new(
            StatusCode::BAD_REQUEST,
            "validation",
            "A device needs its platform's token, and an environment of production or sandbox.",
        ));
    }
    voip_token_allowed(&request.platform, request.voip_token.as_deref())?;
    let id = Uuid::now_v7();
    let secret = random(32);
    let mut conn = relay.db.get().await?;
    diesel::insert_into(device::table)
        .values((
            device::id.eq(id),
            device::secret_digest.eq(digest(&secret)),
            device::platform.eq(&request.platform),
            device::app.eq(&request.app),
            device::environment.eq(&request.environment),
            device::token.eq(&request.token),
            device::voip_token.eq(&request.voip_token),
        ))
        .execute(&mut conn)
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(DeviceCreated { device: id, secret }),
    ))
}

/// The device a request is about, when it carries that device's secret.
async fn authorized(relay: &Relay, id: Uuid, headers: &HeaderMap) -> Result<Device, Problem> {
    let secret = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    let mut conn = relay.db.get().await?;
    let found: Option<Device> = device::table
        .select(Device::as_select())
        .find(id)
        .first(&mut conn)
        .await
        .optional()?;
    match (found, secret) {
        (Some(found), Some(secret)) if found.secret_digest == digest(secret) => Ok(found),
        _ => Err(Problem::new(
            StatusCode::NOT_FOUND,
            "notFound",
            "No such device, or not with that secret. Register the device again.",
        )),
    }
}

/// The tokens the platform issued anew: either or both, each left as it was when absent.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenRequest {
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    voip_token: Option<String>,
}

async fn update_device(
    State(relay): Shared,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<TokenRequest>,
) -> Result<StatusCode, Problem> {
    let device = authorized(&relay, id, &headers).await?;
    if request.token.is_none() && request.voip_token.is_none()
        || request
            .token
            .as_deref()
            .is_some_and(|token| !token_fits(token))
    {
        return Err(Problem::new(
            StatusCode::BAD_REQUEST,
            "validation",
            format!(
                "Give the token the platform issued, voipToken, or both, each at most {MAX_TOKEN_CHARS} characters."
            ),
        ));
    }
    voip_token_allowed(&device.platform, request.voip_token.as_deref())?;
    let mut conn = relay.db.get().await?;
    // Each token is replaced only when given, so the two are kept independently.
    if let Some(token) = &request.token {
        diesel::update(device::table.find(id))
            .set((
                device::token.eq(token),
                device::updated_at.eq(diesel::dsl::now),
            ))
            .execute(&mut conn)
            .await?;
    }
    if let Some(voip_token) = &request.voip_token {
        diesel::update(device::table.find(id))
            .set((
                device::voip_token.eq(voip_token),
                device::updated_at.eq(diesel::dsl::now),
            ))
            .execute(&mut conn)
            .await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_device(
    State(relay): Shared,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, Problem> {
    authorized(&relay, id, &headers).await?;
    let mut conn = relay.db.get().await?;
    diesel::delete(device::table.find(id))
        .execute(&mut conn)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SubscriptionRequest {
    application_server_key: String,
}

#[derive(Serialize)]
struct SubscriptionCreated {
    subscription: Uuid,
    endpoint: String,
}

async fn create_subscription(
    State(relay): Shared,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<SubscriptionRequest>,
) -> Result<(StatusCode, Json<SubscriptionCreated>), Problem> {
    authorized(&relay, id, &headers).await?;
    let key = URL_SAFE_NO_PAD
        .decode(request.application_server_key.trim_end_matches('='))
        .ok()
        .filter(|key| key.len() == 65 && key[0] == 4)
        .ok_or_else(|| {
            Problem::new(
                StatusCode::BAD_REQUEST,
                "validation",
                "applicationServerKey must be the deployment's P-256 push key, uncompressed and base64url, as its GET /api/v1/auth/methods gives it.",
            )
        })?;
    let subscription_id = Uuid::now_v7();
    let push_id = random(32);
    let mut conn = relay.db.get().await?;
    diesel::insert_into(subscription::table)
        .values((
            subscription::id.eq(subscription_id),
            subscription::push_id.eq(&push_id),
            subscription::device.eq(id),
            subscription::application_server_key.eq(key),
        ))
        .execute(&mut conn)
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(SubscriptionCreated {
            subscription: subscription_id,
            endpoint: format!(
                "{}/v1/push/{push_id}",
                relay.config.public_url.trim_end_matches('/')
            ),
        }),
    ))
}

async fn delete_subscription(
    State(relay): Shared,
    Path((id, subscription_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<StatusCode, Problem> {
    authorized(&relay, id, &headers).await?;
    let mut conn = relay.db.get().await?;
    diesel::delete(
        subscription::table.filter(
            subscription::id
                .eq(subscription_id)
                .and(subscription::device.eq(id)),
        ),
    )
    .execute(&mut conn)
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

async fn push(
    State(relay): Shared,
    Path(push_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, Problem> {
    if body.len() > MAX_MESSAGE_BYTES {
        return Err(Problem::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "tooLarge",
            format!("This relay takes messages of at most {MAX_MESSAGE_BYTES} bytes."),
        ));
    }
    if header_str(&headers, "content-encoding") != Some("aes128gcm") || body.is_empty() {
        return Err(Problem::new(
            StatusCode::BAD_REQUEST,
            "badRequest",
            "A push must be encrypted to the phone (RFC 8291), with Content-Encoding: aes128gcm.",
        ));
    }
    let mut conn = relay.db.get().await?;
    let found: Option<(Subscription, Device)> = subscription::table
        .inner_join(device::table)
        .select((Subscription::as_select(), Device::as_select()))
        .filter(subscription::push_id.eq(&push_id))
        .first(&mut conn)
        .await
        .optional()?;
    let Some((subscription, device)) = found else {
        return Err(Problem::new(
            StatusCode::GONE,
            "gone",
            "This subscription no longer exists; stop pushing to it.",
        ));
    };
    let now = chrono::Utc::now();
    let authorization = header_str(&headers, "authorization").unwrap_or_default();
    match vapid::verify(
        authorization,
        &subscription.application_server_key,
        &relay.config.public_url,
        now.timestamp(),
    ) {
        Ok(_) => {}
        Err(VapidError::WrongKey) => {
            return Err(Problem::new(
                StatusCode::FORBIDDEN,
                "wrongKey",
                VapidError::WrongKey.to_string(),
            ));
        }
        Err(other) => {
            return Err(Problem::new(
                StatusCode::UNAUTHORIZED,
                "badAuthorization",
                format!(
                    "{other}. Sign each push as RFC 8292 describes, with the key the subscription was made for."
                ),
            ));
        }
    }
    if let Err(wait) = relay.take(subscription.id) {
        let mut problem = Problem::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rateLimited",
            "This phone is being woken too often; wait before waking it again.",
        );
        problem.retry_after = Some(wait);
        return Err(problem);
    }
    drop(conn);
    let (within, used) = relay
        .usage
        .count(
            &relay.db,
            &subscription.application_server_key,
            relay.config.limits.free_monthly_pushes,
            now,
        )
        .await
        .map_err(internal)?;
    if !within {
        use chrono::TimeZone;
        let next = db::month_of(now)
            .checked_add_months(chrono::Months::new(1))
            .and_then(|day| day.and_hms_opt(0, 0, 0))
            .map(|at| chrono::Utc.from_utc_datetime(&at))
            .unwrap_or(now);
        let mut problem = Problem::new(
            StatusCode::TOO_MANY_REQUESTS,
            "quotaExhausted",
            format!(
                "This deployment has sent {used} pushes through this relay in {}, more than its tier allows. Pushes resume next month; its operator can raise its tier with the relay's operators.",
                now.format("%B %Y")
            ),
        );
        problem.retry_after = Some((next - now).to_std().unwrap_or(Duration::from_secs(3600)));
        return Err(problem);
    }
    let urgency = header_str(&headers, "urgency").unwrap_or("normal");
    let ttl = header_str(&headers, "ttl")
        .and_then(|ttl| ttl.parse::<u64>().ok())
        .map_or(MAX_TTL, |seconds| Duration::from_secs(seconds).min(MAX_TTL));
    let topic = header_str(&headers, "topic").filter(|topic| {
        topic.len() <= 32
            && topic
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    });
    let subscription_id = subscription.id.to_string();
    let call = header_str(&headers, KIND_HEADER) == Some(KIND_CALL);
    let message = Push {
        subscription: &subscription_id,
        ciphertext: &body,
        urgent: urgency == "high",
        ttl,
        topic,
        call,
    };
    let quiet = matches!(urgency, "low" | "very-low");
    let outcome = match device.platform.as_str() {
        "apns" => match (relay.apns.as_ref(), call, device.voip_token.as_deref()) {
            (None, _, _) => Ok(Outcome::Gone),
            // Without the filtering entitlement, the app cannot keep a push from showing, so a
            // push meant to show nothing is not sent.
            (Some(apns), false, _) if quiet && !apns.filtering() => Ok(Outcome::Delivered),
            (Some(apns), false, _) => {
                apns.send(&device.app, &device.environment, &device.token, &message)
                    .await
            }
            // An app that registered no VoIP token is of a version that could not show the
            // call; the ring is not sent to it, as a notification could not ring the phone.
            (Some(_), true, None) => Ok(Outcome::Delivered),
            (Some(apns), true, Some(voip_token)) => {
                match apns
                    .send(&device.app, &device.environment, voip_token, &message)
                    .await
                {
                    // The VoIP token is gone, not the device: its alert token may still stand,
                    // so the device is kept and sent calls again once the app registers a new one.
                    Ok(Outcome::Gone) => {
                        let mut conn = relay.db.get().await?;
                        diesel::update(device::table.find(device.id))
                            .set(device::voip_token.eq(None::<String>))
                            .execute(&mut conn)
                            .await?;
                        Ok(Outcome::Delivered)
                    }
                    other => other,
                }
            }
        },
        "fcm" => match relay.fcm.as_ref() {
            Some(fcm) => fcm.send(&device.token, &message).await,
            None => Ok(Outcome::Gone),
        },
        _ => Ok(Outcome::Gone),
    };
    match outcome {
        Ok(Outcome::Delivered) => {
            relay.usage.pushed(subscription.id).await;
            Ok(StatusCode::CREATED)
        }
        Ok(Outcome::Gone) => {
            let mut conn = relay.db.get().await?;
            diesel::delete(device::table.find(device.id))
                .execute(&mut conn)
                .await?;
            Err(Problem::new(
                StatusCode::GONE,
                "gone",
                "The phone is no longer reachable: the app was removed or its registration replaced. Stop pushing to this subscription.",
            ))
        }
        Ok(Outcome::Busy) => {
            let mut problem = Problem::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "platformBusy",
                "Apple's or Google's push service is overloaded; try again shortly.",
            );
            problem.retry_after = Some(Duration::from_secs(30));
            Err(problem)
        }
        Err(e) => {
            tracing::warn!("a platform refused a push: {e}");
            Err(Problem::new(
                StatusCode::BAD_GATEWAY,
                "platformFailed",
                "Apple's or Google's push service refused the push. The relay's operators have been told.",
            ))
        }
    }
}
