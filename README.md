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

## Running it

It needs PostgreSQL, and brings its own schema up to date at startup.

```
cp relay.example.toml relay.toml   # and fill it in
cargo run --release
```

It listens as plain HTTP; put a TLS proxy in front of it at `public_url`. `RELAY_LOG` sets how
much it logs (`info` by default).

## Quotas

Every deployment key may send `[limits] free_monthly_pushes` a month. A deployment that needs
more is given a tier by adding a row to `key_tier` (its key, as the 65 bytes of the point, and
its monthly pushes). A deployment over its quota is answered `429` `quotaExhausted` with
`Retry-After` until the month turns, and each phone may be woken `subscription_burst` times back
to back and then once every `subscription_interval_seconds` (`429` `rateLimited`).

## Checking it

```
scripts/e2e.py
```

builds and starts the relay against stand-ins for Apple and Google, plays a deployment, and
checks every rule. It needs PostgreSQL (by default the one Aspen's `docker-compose.yaml` starts)
and Python's `cryptography`.

## Licence

GPL-3.0-or-later, as Aspen.
