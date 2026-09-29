//! How many pushes each deployment key has sent this month, and which subscriptions were pushed
//! to, counted in memory and saved every [`FLUSH_INTERVAL`] rather than written with each push,
//! which would make every push wait on the database and every push of one deployment contend
//! for the same row.
//!
//! A key's total is read from the database the first time this relay sees it in a month and
//! after every save, so it includes what other relays have counted up to then. Several relays
//! may therefore together let a deployment past its quota by what they accept in one interval;
//! quotas are for sharing the relay's cost, and that much is noise.

use crate::db::{DbPool, key_tier, key_usage, month_of, subscription};
use chrono::{DateTime, NaiveDate, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use tokio::sync::Mutex;
use uuid::Uuid;

/// How often counts are saved.
pub const FLUSH_INTERVAL: Duration = Duration::from_secs(5);

/// A key's pushes in a month, counted here and not yet saved.
type Unsaved = (Vec<u8>, NaiveDate, i64);

#[derive(Default)]
struct KeyCount {
    /// The month's total as the database last said.
    saved: i64,
    /// Counted here since.
    pending: i64,
    /// Its tier's monthly pushes, if it has one.
    tier: Option<i64>,
}

#[derive(Default)]
struct State {
    counts: HashMap<(Vec<u8>, NaiveDate), KeyCount>,
    pushed: HashSet<Uuid>,
}

#[derive(Default)]
pub struct Usage {
    state: Mutex<State>,
}

impl Usage {
    /// Counts one push by `key`, answering whether it is within the key's quota (its tier's, or
    /// `free` without one) and how many it has sent this month, this one included.
    pub async fn count(
        &self,
        db: &DbPool,
        key: &[u8],
        free: i64,
        now: DateTime<Utc>,
    ) -> anyhow::Result<(bool, i64)> {
        let month = month_of(now);
        let slot = (key.to_vec(), month);
        let known = self.state.lock().await.counts.contains_key(&slot);
        if !known {
            // Read outside the lock; a push racing this one reads the same numbers.
            let (saved, tier) = read(db, key, month).await?;
            self.state
                .lock()
                .await
                .counts
                .entry(slot.clone())
                .or_insert(KeyCount {
                    saved,
                    pending: 0,
                    tier,
                });
        }
        let mut state = self.state.lock().await;
        let count = state.counts.entry(slot).or_default();
        let used = count.saved + count.pending + 1;
        let within = used <= count.tier.unwrap_or(free);
        if within {
            count.pending += 1;
        }
        Ok((within, used))
    }

    /// Notes that a push reached `subscription`, saved with the counts.
    pub async fn pushed(&self, subscription: Uuid) {
        self.state.lock().await.pushed.insert(subscription);
    }

    /// Saves what was counted since the last save and reads back each key's total and tier.
    pub async fn flush(&self, db: &DbPool) -> anyhow::Result<()> {
        let (pending, pushed): (Vec<Unsaved>, Vec<Uuid>) = {
            let mut state = self.state.lock().await;
            let pending = state
                .counts
                .iter_mut()
                .filter(|(_, count)| count.pending > 0)
                .map(|((key, month), count)| {
                    let delta = count.pending;
                    count.saved += delta;
                    count.pending = 0;
                    (key.clone(), *month, delta)
                })
                .collect();
            (pending, state.pushed.drain().collect())
        };
        let mut conn = db.get().await?;
        for (key, month, delta) in &pending {
            let total: i64 = diesel::insert_into(key_usage::table)
                .values((
                    key_usage::application_server_key.eq(key),
                    key_usage::month.eq(month),
                    key_usage::pushes.eq(delta),
                ))
                .on_conflict((key_usage::application_server_key, key_usage::month))
                .do_update()
                .set(key_usage::pushes.eq(key_usage::pushes + delta))
                .returning(key_usage::pushes)
                .get_result(&mut conn)
                .await?;
            let tier: Option<i64> = key_tier::table
                .select(key_tier::monthly_pushes)
                .find(key)
                .first(&mut conn)
                .await
                .optional()?;
            // What other relays counted comes in with the total; what this one counted since
            // the snapshot stays pending.
            if let Some(count) = self
                .state
                .lock()
                .await
                .counts
                .get_mut(&(key.clone(), *month))
            {
                count.saved = total;
                count.tier = tier;
            }
        }
        if !pushed.is_empty() {
            diesel::update(subscription::table.filter(subscription::id.eq_any(&pushed)))
                .set(subscription::last_push_at.eq(diesel::dsl::now))
                .execute(&mut conn)
                .await?;
        }
        // Past months are saved now; only this one's counts are needed.
        let current = month_of(Utc::now());
        self.state
            .lock()
            .await
            .counts
            .retain(|(_, month), count| *month >= current || count.pending > 0);
        Ok(())
    }
}

async fn read(db: &DbPool, key: &[u8], month: NaiveDate) -> anyhow::Result<(i64, Option<i64>)> {
    let mut conn = db.get().await?;
    let saved: Option<i64> = key_usage::table
        .select(key_usage::pushes)
        .find((key, month))
        .first(&mut conn)
        .await
        .optional()?;
    let tier: Option<i64> = key_tier::table
        .select(key_tier::monthly_pushes)
        .find(key)
        .first(&mut conn)
        .await
        .optional()?;
    Ok((saved.unwrap_or(0), tier))
}

/// Saves counts every [`FLUSH_INTERVAL`] until the relay stops.
pub fn spawn_flusher(usage: std::sync::Arc<Usage>, db: DbPool) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(FLUSH_INTERVAL);
        loop {
            tick.tick().await;
            if let Err(e) = usage.flush(&db).await {
                tracing::error!("saving push counts failed: {e}");
            }
        }
    });
}
