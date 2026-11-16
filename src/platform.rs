//! What the relay hands a platform to send, and what the platform said.

use std::time::Duration;

/// One push, as a platform sends it.
pub struct Push<'a> {
    /// The subscription's id, which tells the phone which account and key the push is for.
    pub subscription: &'a str,
    pub ciphertext: &'a [u8],
    /// Whether it is for the person now (`Urgency: high`), or can wait.
    pub urgent: bool,
    pub ttl: Duration,
    /// A later push with the same topic replaces this one, if it is still waiting.
    pub topic: Option<&'a str>,
    /// Whether the push is a call ringing the phone (`Aspen-Push-Kind: call`), sent as the
    /// platform's call push: a VoIP push to the device's VoIP token on iOS, a high-priority
    /// message marked `k: call` on Android (`spec/push.md`, Calls).
    pub call: bool,
}

pub enum Outcome {
    Delivered,
    /// The platform says the device is gone: uninstalled, or its token replaced.
    Gone,
    /// The platform is overloaded or failing; try later.
    Busy,
}
