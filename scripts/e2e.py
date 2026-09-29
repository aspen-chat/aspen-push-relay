#!/usr/bin/env python3
"""Runs the relay against stand-ins for Apple's and Google's push services and checks what it
does, from registering a device to what reaches each platform.

    scripts/e2e.py [--database-url postgres://…/postgres]

It makes a database of its own on the PostgreSQL given (by default the one Aspen's
docker-compose.yaml starts), builds and starts the relay with keys it makes up, plays a
deployment pushing to it, and drops the database afterwards. It needs Python's `cryptography`.
"""

import argparse
import base64
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ROOT = Path(__file__).resolve().parent.parent
DATABASE = "aspen_push_relay_e2e"
APP = "org.aspen.chat"
PROJECT = "aspen-e2e"


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def point(key) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def hkdf(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def encrypt(plaintext: bytes, ua_public: bytes, auth: bytes) -> bytes:
    """RFC 8291, as a deployment does it."""
    ephemeral = ec.generate_private_key(ec.SECP256R1())
    as_public = point(ephemeral)
    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ua_public)
    secret = ephemeral.exchange(ec.ECDH(), peer)
    ikm = hkdf(auth, secret, b"WebPush: info\0" + ua_public + as_public, 32)
    salt = os.urandom(16)
    cek = hkdf(salt, ikm, b"Content-Encoding: aes128gcm\0", 16)
    nonce = hkdf(salt, ikm, b"Content-Encoding: nonce\0", 12)
    record = AESGCM(cek).encrypt(nonce, plaintext + b"\x02", None)
    return salt + (4096).to_bytes(4, "big") + bytes([65]) + as_public + record


def vapid(key, audience: str, expires_in: int = 3600) -> str:
    header = b64(json.dumps({"typ": "JWT", "alg": "ES256"}).encode())
    claims = b64(json.dumps({"aud": audience, "exp": int(time.time()) + expires_in,
                             "sub": "https://chat.example"}).encode())
    der = key.sign(f"{header}.{claims}".encode(), ec.ECDSA(hashes.SHA256()))
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    r, s = decode_dss_signature(der)
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"vapid t={header}.{claims}.{b64(signature)}, k={b64(point(key))}"


class Stand(BaseHTTPRequestHandler):
    """Apple's and Google's services, recording what they are sent. `answers` says what to
    answer next, per path prefix."""
    received: list = []
    answers: dict = {}

    def log_message(self, *args):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.received.append({"path": self.path, "headers": dict(self.headers), "body": body})
        if self.path == "/token":
            reply = (200, {"access_token": "google-access", "expires_in": 3600})
        else:
            prefix = "/3/device/" if self.path.startswith("/3/device/") else "/v1/projects/"
            reply = self.answers.pop(prefix, (200, {}))
        self.send_response(reply[0])
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(reply[1]).encode())


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def call(method: str, url: str, body=None, headers=None) -> tuple[int, dict, bytes]:
    data = body if isinstance(body, bytes) or body is None else json.dumps(body).encode()
    request = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    if isinstance(body, (dict, list)):
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers), error.read()


class Failed(Exception):
    pass


def expect(condition: bool, what: str) -> None:
    if not condition:
        raise Failed(what)
    print(f"e2e: ok: {what}")


def psql(database_url: str, sql: str) -> str:
    done = subprocess.run(["psql", database_url, "-qAtc", sql], check=True, capture_output=True, text=True)
    return done.stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database-url", default="postgres://postgres:aspen_test@127.0.0.1:5432/postgres")
    args = parser.parse_args()
    admin_url = args.database_url
    relay_url = admin_url.rsplit("/", 1)[0] + "/" + DATABASE
    psql(admin_url, f"DROP DATABASE IF EXISTS {DATABASE}")
    psql(admin_url, f"CREATE DATABASE {DATABASE}")

    stand_port = free_port()
    stand = ThreadingHTTPServer(("127.0.0.1", stand_port), Stand)
    threading.Thread(target=stand.serve_forever, daemon=True).start()
    stand_url = f"http://127.0.0.1:{stand_port}"

    work = Path(tempfile.mkdtemp(prefix="relay-e2e-"))
    apple_key = ec.generate_private_key(ec.SECP256R1())
    (work / "apns.p8").write_bytes(apple_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    google_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    (work / "service-account.json").write_text(json.dumps({
        "client_email": "relay@aspen-e2e.iam.gserviceaccount.com",
        "private_key": google_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()).decode(),
        "token_uri": f"{stand_url}/token",
    }))

    subprocess.run(["cargo", "build", "-q"], cwd=ROOT, check=True)
    port = free_port()
    public_url = f"http://127.0.0.1:{port}"
    env = {**os.environ,
           "RELAY_CONFIG": str(work / "none.toml"),
           "RELAY_LISTEN_ADDR": f"127.0.0.1:{port}",
           "RELAY_PUBLIC_URL": public_url,
           "RELAY_DATABASE_URL": relay_url,
           "RELAY_APNS__TEAM_ID": "TEAM123456",
           "RELAY_APNS__KEY_ID": "KEY1234567",
           "RELAY_APNS__KEY_PATH": str(work / "apns.p8"),
           "RELAY_APNS__TOPICS": APP,
           "RELAY_APNS__PRODUCTION_URL": stand_url,
           "RELAY_APNS__SANDBOX_URL": stand_url,
           "RELAY_FCM__PROJECT_ID": PROJECT,
           "RELAY_FCM__SERVICE_ACCOUNT_PATH": str(work / "service-account.json"),
           "RELAY_FCM__URL": stand_url,
           "RELAY_LIMITS__FREE_MONTHLY_PUSHES": "5",
           "RELAY_LIMITS__SUBSCRIPTION_BURST": "3"}
    relay = subprocess.Popen([str(ROOT / "target/debug/aspen-push-relay")], env=env,
                             stdout=subprocess.DEVNULL, stderr=open(work / "relay.log", "w"))
    try:
        for _ in range(100):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.1)
        run(public_url, apple_key, google_key)
        # Counts are saved every few seconds, not with each push.
        time.sleep(6)
        expect(psql(relay_url, "SELECT sum(pushes) FROM key_usage") == "6",
               "every push accepted is counted in the database within a few seconds")
        print("e2e: every check passed")
        return 0
    except Failed as failure:
        print(f"e2e: FAILED: {failure}\n(relay log: {work / 'relay.log'})")
        return 1
    finally:
        relay.terminate()
        relay.wait()
        stand.shutdown()
        psql(admin_url, f"DROP DATABASE IF EXISTS {DATABASE}")


def run(relay: str, apple_key, google_key) -> None:
    status, _, body = call("POST", f"{relay}/v1/devices", {"platform": "apns", "app": "com.other", "token": "t"})
    expect(status == 400 and json.loads(body)["code"] == "unknownApp", "an app this relay does not serve is refused")

    status, _, body = call("POST", f"{relay}/v1/devices", {"platform": "apns", "app": APP, "token": "apple-token-1"})
    expect(status == 201, "an iOS device registers")
    device = json.loads(body)
    auth = {"Authorization": f"Bearer {device['secret']}"}
    status, _, _ = call("PATCH", f"{relay}/v1/devices/{device['device']}", {"token": "apple-token-2"},
                        {"Authorization": "Bearer wrong"})
    expect(status == 404, "a device is not changed without its secret")
    status, _, _ = call("PATCH", f"{relay}/v1/devices/{device['device']}", {"token": "apple-token-2"}, auth)
    expect(status == 204, "a device's token is replaced with its secret")

    deployment = ec.generate_private_key(ec.SECP256R1())
    status, _, body = call("POST", f"{relay}/v1/devices/{device['device']}/subscriptions",
                           {"applicationServerKey": b64(point(deployment))}, auth)
    expect(status == 201, "the device subscribes to a deployment's key")
    subscription = json.loads(body)
    endpoint = subscription["endpoint"]
    expect(endpoint.startswith(f"{relay}/v1/push/"), "the endpoint is on the relay's public URL")

    phone = ec.generate_private_key(ec.SECP256R1())
    secret = os.urandom(16)
    ciphertext = encrypt(b'{"v":1,"kind":"message"}', point(phone), secret)
    push_headers = {"Content-Encoding": "aes128gcm", "TTL": "600", "Urgency": "high",
                    "Topic": "0190f0a0000070008000000000000011"}

    status, _, body = call("POST", endpoint, ciphertext,
                           {**push_headers, "Authorization": vapid(ec.generate_private_key(ec.SECP256R1()), relay)})
    expect(status == 403 and json.loads(body)["code"] == "wrongKey", "a push signed by another key is refused")
    status, _, body = call("POST", endpoint, ciphertext,
                           {**push_headers, "Authorization": vapid(deployment, "https://elsewhere.example")})
    expect(status == 401, "a push signed for another relay is refused")
    status, _, _ = call("POST", endpoint, ciphertext, {"Authorization": vapid(deployment, relay)})
    expect(status == 400, "an unencrypted push is refused")

    Stand.received.clear()
    status, _, _ = call("POST", endpoint, ciphertext, {**push_headers, "Authorization": vapid(deployment, relay)})
    expect(status == 201, "a signed, encrypted push is accepted")
    sent = [r for r in Stand.received if r["path"].startswith("/3/device/")]
    expect(len(sent) == 1 and sent[0]["path"] == "/3/device/apple-token-2", "it reaches APNs for the device's token")
    headers = {k.lower(): v for k, v in sent[0]["headers"].items()}
    payload = json.loads(sent[0]["body"])
    expect(headers["apns-topic"] == APP and headers["apns-push-type"] == "alert"
           and headers["apns-priority"] == "10"
           and headers["apns-collapse-id"] == push_headers["Topic"],
           "as a high-priority alert for the app, collapsed by topic")
    expect(payload["aps"]["mutable-content"] == 1
           and payload["aps"]["alert"] == {"loc-key": "notification.placeholder"},
           "with a placeholder the notification service extension replaces")
    expect(payload["aspen"] == {"s": subscription["subscription"], "c": b64(ciphertext)},
           "carrying the subscription's id and the ciphertext, untouched")
    token = headers["authorization"].removeprefix("bearer ").removeprefix("Bearer ")
    signing_input, signature = token.rsplit(".", 1)
    raw = unb64(signature)
    apple_key.public_key().verify(
        encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")),
        signing_input.encode(), ec.ECDSA(hashes.SHA256()))
    token_header = json.loads(unb64(signing_input.split(".")[0]))
    token_claims = json.loads(unb64(signing_input.split(".")[1]))
    expect(token_header == {"alg": "ES256", "kid": "KEY1234567"} and token_claims["iss"] == "TEAM123456",
           "signed with the team's key, which Apple can check")

    Stand.received.clear()
    status, _, _ = call("POST", endpoint, ciphertext,
                        {**push_headers, "Urgency": "low", "Authorization": vapid(deployment, relay)})
    expect(status == 201 and not Stand.received,
           "a push that shows nothing is accepted and not sent, without the filtering entitlement")

    status, headers, body = call("POST", endpoint, ciphertext, {**push_headers, "Authorization": vapid(deployment, relay)})
    status, headers, body = call("POST", endpoint, ciphertext, {**push_headers, "Authorization": vapid(deployment, relay)})
    expect(status == 429 and json.loads(body)["code"] == "rateLimited" and "retry-after" in {k.lower() for k in headers},
           "a phone woken too often is refused for a while")

    status, _, body = call("POST", f"{relay}/v1/devices",
                           {"platform": "fcm", "app": PROJECT, "token": "google-token"})
    android = json.loads(body)
    status, _, body = call("POST", f"{relay}/v1/devices/{android['device']}/subscriptions",
                           {"applicationServerKey": b64(point(deployment))},
                           {"Authorization": f"Bearer {android['secret']}"})
    android_endpoint = json.loads(body)["endpoint"]
    android_subscription = json.loads(body)["subscription"]
    Stand.received.clear()
    status, _, _ = call("POST", android_endpoint, ciphertext, {**push_headers, "Authorization": vapid(deployment, relay)})
    expect(status == 201, "a push to an Android device is accepted")
    token_request = next(r for r in Stand.received if r["path"] == "/token")
    assertion = token_request["body"].decode().split("assertion=")[1]
    claims = json.loads(unb64(assertion.split(".")[1]))
    signing_input, signature = assertion.rsplit(".", 1)
    google_key.public_key().verify(unb64(signature), signing_input.encode(),
                                   padding.PKCS1v15(), hashes.SHA256())
    expect(claims["scope"] == "https://www.googleapis.com/auth/firebase.messaging",
           "the relay asks Google for a messaging token, signed with its service account's key")
    message = json.loads(next(r for r in Stand.received if r["path"].startswith("/v1/projects/"))["body"])["message"]
    expect(message["token"] == "google-token"
           and message["data"] == {"s": android_subscription, "c": b64(ciphertext)}
           and message["android"]["priority"] == "HIGH"
           and message["android"]["collapse_key"] == push_headers["Topic"],
           "it reaches FCM as a high-priority data message with the subscription's id and the ciphertext")

    status, _, body = call("POST", android_endpoint, ciphertext, {**push_headers, "Authorization": vapid(deployment, relay)})
    status, headers, body = call("POST", android_endpoint, ciphertext, {**push_headers, "Authorization": vapid(deployment, relay)})
    expect(status == 429 and json.loads(body)["code"] == "quotaExhausted" and "retry-after" in {k.lower() for k in headers},
           "a deployment past its monthly quota is refused until next month")

    other = ec.generate_private_key(ec.SECP256R1())
    status, _, body = call("POST", f"{relay}/v1/devices/{android['device']}/subscriptions",
                           {"applicationServerKey": b64(point(other))},
                           {"Authorization": f"Bearer {android['secret']}"})
    other_endpoint = json.loads(body)["endpoint"]
    Stand.answers["/v1/projects/"] = (404, {"error": {"status": "NOT_FOUND"}})
    status, _, body = call("POST", other_endpoint, ciphertext, {**push_headers, "Authorization": vapid(other, relay)})
    expect(status == 410, "a device Google says is gone is gone to deployments")
    status, _, _ = call("POST", android_endpoint, ciphertext, {**push_headers, "Authorization": vapid(deployment, relay)})
    expect(status == 410, "and every subscription of it with it")

    status, _, _ = call("DELETE", f"{relay}/v1/devices/{device['device']}", None, auth)
    status, _, _ = call("POST", endpoint, ciphertext, {**push_headers, "Authorization": vapid(deployment, relay)})
    expect(status == 410, "a device its app removed is gone")


if __name__ == "__main__":
    sys.exit(main())
