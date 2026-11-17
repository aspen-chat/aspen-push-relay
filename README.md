# Aspen push relay

Aspen deployments are run by anyone, but the Aspen app on a phone is published once, and only
its publisher's credentials can wake it: an Apple push key sends to every user of every app of
its team, and a Firebase service account to every user of its project, so neither can be handed
to the deployments. The relay holds them, and wakes the app's phones for any deployment, without
learning what it wakes them for.

The protocol is `spec/push.md` in the Aspen repository. In short:

1. The app registers its phone (`POST /v1/devices`, with its APNs or FCM token) and, for each
   deployment account it signs in to, subscribes to that deployment's push key
   (`POST /v1/devices/{device}/subscriptions`), getting an endpoint URL it gives the deployment.
2. The deployment pushes to the endpoint with Web Push (RFC 8030): a message encrypted to the
   phone (RFC 8291) and signed with its key (RFC 8292). The relay accepts only pushes signed by
   the key a subscription was made for, and cannot read them.
3. The relay hands the ciphertext to Apple or Google with the subscription's id; the app
   decrypts it, fetches the message from the deployment, and shows it.
4. A push marked `Aspen-Push-Kind: call` rings the phone (`spec/push.md`, Calls): on iOS it goes
   as a VoIP push, to the `.voip` topic at priority 10, to the `voipToken` the app registered
   beside its token (an app that registered none is sent no calls); on Android as a high-priority
   data message marked `k: call`. The relay learns that a call is ringing the phone, and nothing
   else.

## Running it

It needs PostgreSQL, and brings its own schema up to date at startup. `database_url` is a libpq
connection string, a URL or `key=value` pairs, and reaches PostgreSQL over TLS (OpenSSL's, as
libpq's) as libpq's parameters say: `sslmode` (`disable`, `prefer` by default, `require`,
`verify-ca`, `verify-full`), `sslrootcert` (a file of the authorities to trust, or `system`), and
`sslcert` and `sslkey` (a client certificate). Use `verify-full`, which checks the certificate names
the host; `src/database.rs` says what each mode checks.

```
cp relay.example.toml relay.toml   # and fill it in
cargo run --release
```

It listens as plain HTTP; put a TLS proxy in front of it at `public_url`. It logs to standard
output, and `RELAY_LOG` sets how much (`info` by default). At `info` every request it refuses is
logged with its route (the template, never the path, since a push's path is a capability), status,
problem code, and detail, so an app that cannot register or a deployment whose pushes are refused
can be told why from here; `RELAY_LOG=info,aspen_push_relay::api=warn` leaves them out.

## Building it for a server

A binary built against this machine's libraries needs at least their versions wherever it runs,
so a rolling-release workstation's build refuses to start on a long-term release. A relay that
leaves the machine it was built on is built against Debian 12 instead, for x86-64 or 64-bit ARM,
on an x86-64 Linux machine with clang and lld:

```
scripts/baseline_build.py --arch x86_64    # or --arch aarch64
```

It fetches a Debian 12 sysroot into `target/cross/<arch>-bookworm/`, builds there, and checks the
result: the architecture, no glibc symbol newer than Debian 12's, no shared library but the C
runtime, OpenSSL, and libpq, and the binary starting (`--version`) against the sysroot's own
libraries, under Debian's user-mode emulator on ARM. The binary runs on Debian 12, Ubuntu 24.04,
Raspberry Pi OS Bookworm, and newer, which need only `libssl3`. `scripts/baseline_build.py --arch
ARCH out` names the directory it lands in, and CI builds both and keeps each as an artifact. The
script is a copy of aspen-chat-server's, which builds its servers the same way.

## Quotas

Every deployment key may send `[limits] free_monthly_pushes` a month. A deployment that needs
more is given a tier by adding a row to `key_tier` (its key, as the 65 bytes of the point, and
its monthly pushes). A deployment over its quota is answered `429` `quotaExhausted` with
`Retry-After` until the month turns, and each phone may be woken `subscription_burst` times back
to back and then once every `subscription_interval_seconds` (`429` `rateLimited`). The free
quota is 200,000 pushes a month unless `relay.toml` says otherwise.

Counts are kept in memory and saved every five seconds (`src/usage.rs`), and at shutdown, so a
push costs the database one indexed read and no write. Several relays behind one address each
read the others' counts at every save, so together they may let a deployment past its quota by
what they accept in five seconds.

## Checking it

```
scripts/e2e.py
```

builds and starts the relay against stand-ins for Apple and Google, plays a deployment, and
checks every rule. It needs PostgreSQL (by default the one Aspen's `docker-compose.yaml` starts)
and Python's `cryptography`.

## Licence

MPL-2.0, as Aspen.
