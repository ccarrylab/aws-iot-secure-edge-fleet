#!/usr/bin/env python3
"""
Secure Edge Fleet Device Agent

- Fleet Provisioning by Claim (full handshake, SUBACK-awaited)
- Switches to permanent device certificate
- Telemetry that survives a dropped connection
- AWS IoT Jobs + OTA, with rollback that also survives a build that will not start
- systemd readiness/watchdog + ota-boot-guard.sh state bookkeeping

Configuration is read from the environment (see CONFIG block). Nothing here
should require editing this file per deployment.
"""

import json
import logging
import os
import secrets
import signal
import sys
import threading
import time
from pathlib import Path

from awsiot import mqtt_connection_builder
from awscrt import mqtt

from ota_handler import OTAHandler, MAX_DOWNLOAD_BYTES


# -------------------------------------------------
# Logging
# -------------------------------------------------
class _JsonFormatter(logging.Formatter):
    """One JSON object per line, so IoT-shipped logs are parseable."""

    def format(self, record):
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def _setup_logging() -> None:
    handler = logging.StreamHandler(sys.stdout)
    if os.environ.get("LOG_FORMAT", "").strip().lower() == "json":
        handler.setFormatter(_JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
        )
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(os.environ.get("LOG_LEVEL", "INFO").strip().upper() or "INFO")


log = logging.getLogger("agent")


# -------------------------------------------------
# Configuration
# -------------------------------------------------
# The committed endpoint is account-specific. Read it from the environment and
# let `terraform output` feed it; editing this file per deployment does not scale
# and puts account identifiers in git history.
IOT_ENDPOINT = os.environ.get(
    "IOT_ENDPOINT", "a3m4rx2lnx5xlz-ats.iot.us-east-1.amazonaws.com"
)
TEMPLATE_NAME = os.environ.get(
    "PROVISIONING_TEMPLATE", "secure-edge-fleet-prov-template"
)

# Optional: a command that must exit 0 for a build to count as healthy. Without
# it the handler falls back to "the payload directory is not empty", which only
# proves an extract happened, not that the agent boots.
_health_cmd_raw = os.environ.get("OTA_HEALTH_CHECK_CMD", "").strip()
HEALTH_CHECK_CMD = _health_cmd_raw.split() if _health_cmd_raw else None

CERTS_DIR = Path(os.environ.get("CERTS_DIR", "certs"))
CLAIM_CERT = CERTS_DIR / "claim-certificate.pem"
CLAIM_KEY = CERTS_DIR / "claim-private.key"
ROOT_CA = CERTS_DIR / "AmazonRootCA1.pem"

DEVICE_CERT = CERTS_DIR / "device-certificate.pem"
DEVICE_KEY = CERTS_DIR / "device-private.key"
THING_NAME_FILE = CERTS_DIR / "thing_name.txt"
SERIAL_FILE = CERTS_DIR / "serial"

# Optional: IoT role alias for the credential provider. When set, the agent
# mints short-lived AWS credentials from its own certificate and reads OTA
# objects straight from S3, so nothing expires. When unset it falls back to the
# presigned packageUrl, which is what every release before this did.
ROLE_ALIAS = os.environ.get("OTA_ROLE_ALIAS", "").strip()
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")

STATE_DIR_DEFAULT = "/var/lib/edge-agent"

THING_NAME = None


# -------------------------------------------------
# systemd integration
# -------------------------------------------------
def sd_notify(message: str) -> bool:
    """Send a datagram to systemd's notify socket.

    A no-op when not running under systemd, so this is safe interactively.
    """
    addr = os.environ.get("NOTIFY_SOCKET")
    if not addr:
        return False
    try:
        import socket

        if addr.startswith("@"):
            addr = "\0" + addr[1:]
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            sock.connect(addr)
            sock.sendall(message.encode("utf-8"))
        finally:
            sock.close()
        return True
    except Exception as e:  # never let notification failure kill the agent
        log.debug("sd_notify(%r) failed: %s", message, e)
        return False


def _watchdog_interval() -> float:
    """Half of WatchdogSec, per systemd's own guidance."""
    usec = os.environ.get("WATCHDOG_USEC")
    if not usec:
        return 0.0
    try:
        return max(2.0, float(usec) / 1_000_000.0 / 2.0)
    except ValueError:
        return 0.0


class Watchdog:
    """Keeps the systemd watchdog fed while the main loop is alive.

    If this thread stops feeding, systemd kills and restarts the unit - which
    is the whole point: a hung agent is indistinguishable from a dead one to
    everything upstream.
    """

    def __init__(self, interval: float):
        self.interval = interval
        self._stop = threading.Event()
        self._thread = None

    def start(self) -> None:
        if self.interval <= 0.0 or not os.environ.get("NOTIFY_SOCKET"):
            if self.interval > 0.0:
                log.info("WATCHDOG_USEC set but NOTIFY_SOCKET absent - not a systemd unit")
            return
        sd_notify("READY=1")
        self._thread = threading.Thread(target=self._run, daemon=True, name="watchdog")
        self._thread.start()
        log.info("sd_notify READY=1 sent; watchdog every %.0fs", self.interval)

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            sd_notify("WATCHDOG=1")

    def stop(self) -> None:
        self._stop.set()


# -------------------------------------------------
# Boot guard state
# -------------------------------------------------
def resolve_state_dir() -> Path:
    """Where ota-boot-guard.sh expects `pending`.

    Must AGREE with the guard, which defaults to /var/lib/edge-agent. Resolved
    once at startup, with a writability probe, so a misconfigured unit fails
    loudly here instead of silently disarming rollback.
    """
    for candidate in (
        os.environ.get("OTA_STATE_DIR"),
        STATE_DIR_DEFAULT,
        str(Path.cwd()),
    ):
        if not candidate:
            continue
        path = Path(candidate)
        try:
            path.mkdir(parents=True, exist_ok=True)
            probe = path / ".write-probe"
            probe.touch()
            probe.unlink()
            return path
        except OSError:
            continue
    return Path.cwd()


class BootGuard:
    """Arms and confirms the local rollback guard.

    `pending` holds the PREVIOUS version, in the exact format the shell guard
    reads. pending.json additionally records the job that is mid-confirmation,
    so the SUCCEEDED report can be deferred until the new build has actually
    started under its own power.
    """

    def __init__(self, state_dir: Path):
        self.dir = state_dir
        self.pending = state_dir / "pending"
        self.boot_count = state_dir / "boot_count"
        self.meta = state_dir / "pending.json"

    def arm(self, previous: str, job_id: str, version: str) -> None:
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            self.pending.write_text(previous)
            self.meta.write_text(
                json.dumps({"previous": previous, "jobId": job_id, "version": version})
            )
            # A new activation starts a fresh count; a stale counter from an
            # earlier incident must not immediately trigger a rollback.
            try:
                self.boot_count.unlink()
            except FileNotFoundError:
                pass
            log.info("boot guard armed: rollback target %s (job %s)", previous, job_id or "?")
        except OSError as e:
            log.warning("boot guard: could not arm pending state: %s", e)

    def read(self):
        if not self.pending.exists():
            return None
        try:
            previous = self.pending.read_text().strip()
        except OSError as e:
            log.warning("boot guard: unreadable pending file: %s", e)
            return None
        meta = {}
        try:
            meta = json.loads(self.meta.read_text())
        except FileNotFoundError:
            pass
        except (OSError, ValueError) as e:
            log.warning("boot guard: unreadable pending.json: %s", e)
        merged = {"previous": previous}
        merged.update(meta)
        return merged

    def confirm(self) -> None:
        for path in (self.pending, self.boot_count, self.meta):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            except OSError as e:
                log.warning("boot guard: could not clear %s: %s", path, e)
        log.info("boot guard confirmed - this build is healthy")


# -------------------------------------------------
# Identity and secrets
# -------------------------------------------------
def _hardware_serial():
    """A serial that identifies the physical board, when the platform exposes one."""
    for path in ("/sys/class/dmi/id/product_serial", "/etc/machine-id"):
        try:
            value = Path(path).read_text().strip()
        except OSError:
            continue
        if value and value.lower() not in ("none", "0", "to be filled by o.e.m."):
            return value[-16:]
    return None


def load_or_create_serial() -> str:
    """Stable device identity, persisted on first boot.

    Published atomically (temp file, then hard link), so it is never observed
    empty. An empty file left by an older crash is discarded and regenerated.
    """
    CERTS_DIR.mkdir(parents=True, exist_ok=True)

    try:
        existing = SERIAL_FILE.read_text(encoding="utf-8").strip()
        if existing:
            return existing
        SERIAL_FILE.unlink(missing_ok=True)
    except FileNotFoundError:
        pass

    serial = _hardware_serial() or secrets.token_hex(8)
    tmp = SERIAL_FILE.with_name("%s.%d.tmp" % (SERIAL_FILE.name, os.getpid()))
    fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.write(fd, serial.encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.link(tmp, SERIAL_FILE)  # atomic; fails if another process won the race
    except FileExistsError:
        return SERIAL_FILE.read_text(encoding="utf-8").strip()
    finally:
        tmp.unlink(missing_ok=True)
    log.info("generated device serial: %s", serial)
    return serial


def ensure_root_ca() -> None:
    """Vendored, not downloaded.

    Fetching the trust anchor over the network you are about to trust, once, on
    a device you may never physically reach again, is a bootstrap nobody can
    audit. It also crashed on a clean checkout: urlretrieve() was called before
    certs/ existed, so main() died on its first statement.
    """
    if not ROOT_CA.exists():
        raise SystemExit(
            "Missing %s.\n"
            "Ship AmazonRootCA1.pem with the agent image rather than downloading the\n"
            "trust anchor at boot, e.g. during your image build:\n"
            "  mkdir -p device-agent/certs && curl -fsSL -o device-agent/certs/AmazonRootCA1.pem \\\n"
            "      https://www.amazontrust.com/repository/AmazonRootCA1.pem\n"
            "(and un-ignore certs/AmazonRootCA1.pem in .gitignore - the private keys stay out)"
            % ROOT_CA
        )


def _write_secret(path: Path, data: str) -> None:
    """Create the file already at 0600.

    write_text() + os.chmod() left a window where the private key existed under
    the process umask - typically world-readable.
    """
    fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data.encode())
        os.fsync(fd)  # a key that vanishes in a power cut means a re-provision
    finally:
        os.close(fd)


def save_device_credentials(cert_pem: str, key_pem: str, thing_name: str) -> None:
    CERTS_DIR.mkdir(parents=True, exist_ok=True)
    _write_secret(DEVICE_CERT, cert_pem)
    _write_secret(DEVICE_KEY, key_pem)
    _write_secret(THING_NAME_FILE, thing_name)
    log.info("saved permanent credentials for thing: %s", thing_name)


def load_existing_thing():
    if DEVICE_CERT.exists() and DEVICE_KEY.exists() and THING_NAME_FILE.exists():
        return THING_NAME_FILE.read_text().strip()
    return None


# -------------------------------------------------
# Connection
# -------------------------------------------------
def build_connection(client_id: str, cert: Path, key: Path, clean_session: bool, on_resume=None):
    """One place that builds connections, so both call sites get the will.

    Nothing previously published a non-online status, so a device that died
    mid-heartbeat stayed "status": "online" in telemetry forever.
    """
    will = mqtt.Will(
        topic="secure-edge-fleet/telemetry/%s" % client_id,
        payload=json.dumps(
            {"thingName": client_id, "status": "offline", "timestamp": 0}
        ),
        qos=mqtt.QoS.AT_LEAST_ONCE,
    )

    def on_connection_interrupted(connection, error, **kwargs):
        log.warning("connection interrupted: %s", error)

    def on_connection_resumed(connection, return_code, session_present, **kwargs):
        log.info(
            "connection resumed: return_code=%s session_present=%s",
            return_code,
            session_present,
        )
        # AWS IoT's MQTT 3.1.1 session persistence is limited; re-subscribing
        # idempotently is the safe pattern.
        if not session_present and on_resume is not None:
            log.info("session not present - re-subscribing")
            try:
                on_resume()
            except Exception as e:
                log.warning("re-subscribe failed: %s", e)

    return mqtt_connection_builder.mtls_from_path(
        endpoint=IOT_ENDPOINT,
        cert_filepath=str(cert),
        pri_key_filepath=str(key),
        ca_filepath=str(ROOT_CA),
        client_id=client_id,
        clean_session=clean_session,
        keep_alive_secs=30,
        will=will,
        on_connection_interrupted=on_connection_interrupted,
        on_connection_resumed=on_connection_resumed,
    )


# -------------------------------------------------
# Fleet Provisioning
# -------------------------------------------------
class FleetProvisioner:
    def __init__(self, mqtt_connection, serial: str):
        self.mqtt = mqtt_connection
        self.serial = serial
        self.ownership_token = None
        self.certificate_pem = None
        self.private_key = None
        self.thing_name = None
        self.done = False
        self.error = None

    def _sub(self, topic: str, callback) -> None:
        """Subscribe and WAIT for the SUBACK - no sleep-based guessing.

        time.sleep(1) was a guess that the subscription had landed. On a slow
        first TLS handshake the create-request went out before the
        accepted-topic subscription existed, the response went nowhere, and
        ninety seconds later you got "Provisioning timed out" with no cause.
        """
        future, _ = self.mqtt.subscribe(
            topic=topic,
            qos=mqtt.QoS.AT_LEAST_ONCE,
            callback=callback,
        )
        future.result(timeout=15)
        log.debug("subscribed to %s", topic)

    def start(self) -> None:
        self._sub("$aws/certificates/create/json/accepted", self._on_create_accepted)
        self._sub("$aws/certificates/create/json/rejected", self._on_create_rejected)
        base = "$aws/provisioning-templates/%s/provision/json" % TEMPLATE_NAME
        self._sub("%s/accepted" % base, self._on_register_accepted)
        self._sub("%s/rejected" % base, self._on_register_rejected)

        log.info("requesting new device certificate...")
        self.mqtt.publish(
            topic="$aws/certificates/create/json",
            payload=json.dumps({}),
            qos=mqtt.QoS.AT_LEAST_ONCE,
        )

    # Every callback is guarded. Unguarded, a KeyError inside one is swallowed
    # by the MQTT thread and the operator only ever sees the generic timeout.
    def _on_create_accepted(self, topic, payload, dup, qos, retain, **kwargs):
        try:
            data = json.loads(payload)
            log.info("certificate create accepted")
            self.ownership_token = data["certificateOwnershipToken"]
            self.certificate_pem = data["certificatePem"]
            self.private_key = data["privateKey"]
            register_payload = {
                "certificateOwnershipToken": self.ownership_token,
                "parameters": {"SerialNumber": self.serial},
            }
            log.info("registering thing with template %s...", TEMPLATE_NAME)
            self.mqtt.publish(
                topic="$aws/provisioning-templates/%s/provision/json" % TEMPLATE_NAME,
                payload=json.dumps(register_payload),
                qos=mqtt.QoS.AT_LEAST_ONCE,
            )
        except Exception as e:
            self.error = "certificate create callback failed: %r" % (e,)
            log.exception("certificate create callback failed")
            self.done = True

    def _on_create_rejected(self, topic, payload, dup, qos, retain, **kwargs):
        try:
            data = json.loads(payload)
            self.error = "Certificate create rejected: %s" % (data,)
        except Exception as e:
            self.error = "certificate create rejected (unparseable): %r" % (e,)
        log.error("%s", self.error)
        self.done = True

    def _on_register_accepted(self, topic, payload, dup, qos, retain, **kwargs):
        try:
            data = json.loads(payload)
            log.info("RegisterThing accepted")
            self.thing_name = data["thingName"]
            save_device_credentials(
                self.certificate_pem, self.private_key, self.thing_name
            )
            self.done = True
        except Exception as e:
            self.error = "register callback failed: %r" % (e,)
            log.exception("register callback failed")
            self.done = True

    def _on_register_rejected(self, topic, payload, dup, qos, retain, **kwargs):
        try:
            data = json.loads(payload)
            self.error = "RegisterThing rejected: %s" % (data,)
        except Exception as e:
            self.error = "RegisterThing rejected (unparseable): %r" % (e,)
        log.error("%s", self.error)
        self.done = True

    def wait(self, timeout: int = 90) -> bool:
        start = time.time()
        while not self.done and (time.time() - start) < timeout:
            time.sleep(0.5)
        if not self.done:
            self.error = "Provisioning timed out"
        return self.error is None


# -------------------------------------------------
# Main
# -------------------------------------------------
def main():
    global THING_NAME

    _setup_logging()
    log.info("Secure Edge Fleet agent starting (endpoint=%s)", IOT_ENDPOINT)

    if not os.environ.get("IOT_ENDPOINT"):
        log.warning(
            "IOT_ENDPOINT is not set; using the value compiled into this file. "
            "Set IOT_ENDPOINT in the unit environment instead of editing source."
        )

    ensure_root_ca()

    state_dir = resolve_state_dir()
    guard = BootGuard(state_dir)
    log.info("boot guard state dir: %s", state_dir)
    if not os.environ.get("OTA_STATE_DIR") and str(state_dir) != STATE_DIR_DEFAULT:
        log.warning(
            "boot guard state dir resolved to %s, but ota-boot-guard.sh defaults to %s. "
            "Set OTA_STATE_DIR in BOTH the unit and the guard, or rollback will look "
            "in the wrong place.",
            state_dir,
            STATE_DIR_DEFAULT,
        )

    existing = load_existing_thing()

    if existing:
        THING_NAME = existing
        log.info("found existing device credentials for %s", THING_NAME)
    else:
        # No permanent credentials yet: provision with the claim certificate.
        serial = load_or_create_serial()
        claim_connection = build_connection(
            "claim-%s" % serial, CLAIM_CERT, CLAIM_KEY, clean_session=True
        )
        claim_connection.connect().result()
        log.info("connected with claim credentials as claim-%s", serial)

        provisioner = FleetProvisioner(claim_connection, serial=serial)
        provisioner.start()
        if not provisioner.wait():
            log.error("provisioning failed: %s", provisioner.error)
            try:
                claim_connection.disconnect().result()
            except Exception:
                pass
            sys.exit(1)

        THING_NAME = provisioner.thing_name
        log.info("provisioning complete: thing=%s", THING_NAME)
        try:
            claim_connection.disconnect().result()
        except Exception as e:
            log.warning("claim disconnect failed: %s", e)

    # -------------------------------------------------
    # Permanent connection
    # -------------------------------------------------
    resume_holder = {"fn": None}

    def _on_resume():
        if resume_holder["fn"] is not None:
            resume_holder["fn"]()

    mqtt_connection = build_connection(
        THING_NAME, DEVICE_CERT, DEVICE_KEY, clean_session=False, on_resume=_on_resume
    )
    mqtt_connection.connect().result()
    log.info("connected with permanent credentials as %s", THING_NAME)

    # -------------------------------------------------
    # Jobs / OTA
    # -------------------------------------------------
    current_job = {"id": None}
    ota_lock = threading.Lock()
    started_jobs = set()
    restart_requested = threading.Event()

    def publish_job_update(status: str, details: dict, job_id=None) -> None:
        jid = job_id or current_job["id"]
        if not jid:
            return
        payload = {
            "status": status,
            "statusDetails": {k: str(v) for k, v in details.items()},
        }
        try:
            mqtt_connection.publish(
                topic="$aws/things/%s/jobs/%s/update" % (THING_NAME, jid),
                payload=json.dumps(payload),
                qos=mqtt.QoS.AT_LEAST_ONCE,
            )
            log.info("[Jobs] reported %s for job %s", status, jid)
        except Exception as e:
            # A status report that cannot be sent must not take down the agent;
            # the job will be retried by AWS until it times out.
            log.warning("[Jobs] could not report %s for %s: %s", status, jid, e)

    def on_ota_status(status: str, details: dict) -> None:
        """Handler -> job status, with the restart handshake spliced in.

        The handler reports SUCCEEDED the moment a build is activated. That is
        premature: the new build has not RUN yet, and activation is exactly the
        moment a device can become unreachable. So SUCCEEDED is held back - we
        arm the boot guard, restart, and report SUCCEEDED only after the new
        build has come up under its own power and confirmed (see the startup
        block below). If it never confirms, the shell guard rolls back.
        """
        if status == "SUCCEEDED" and details.get("previous"):
            guard.arm(
                previous=str(details["previous"]),
                job_id=current_job["id"] or "",
                version=str(details.get("version", "")),
            )
            publish_job_update(
                "IN_PROGRESS",
                {"step": "restarting", "version": details.get("version", "")},
            )
            log.info(
                "activated %s - restarting to confirm before reporting SUCCEEDED",
                details.get("version"),
            )
            restart_requested.set()
            return
        publish_job_update(status, details)

    # Wire the credential-provider fetcher only when an alias is configured.
    # Absent it, the handler keeps requiring a presigned https packageUrl, so
    # this is a no-op for fleets that have not adopted the S3 path yet.
    ota_fetcher = None
    if ROLE_ALIAS:
        try:
            from s3_fetch import make_fetcher

            ota_fetcher = make_fetcher(
                endpoint=IOT_ENDPOINT,
                role_alias=ROLE_ALIAS,
                thing_name=THING_NAME,
                cert_path=str(DEVICE_CERT),
                key_path=str(DEVICE_KEY),
                ca_path=str(ROOT_CA),
                region=AWS_REGION,
                # FIX: thread OTAHandler's own size cap through explicitly, so
                # the S3 path and the HTTPS path share one source of truth for
                # the maximum package size instead of s3_fetch silently using
                # its own separate default.
                max_bytes=MAX_DOWNLOAD_BYTES,
            )
            log.info("OTA downloads will use the credential provider (alias %s)", ROLE_ALIAS)
        except Exception:
            log.exception("could not build the S3 fetcher - falling back to presigned URLs")
            ota_fetcher = None
    else:
        log.info("OTA_ROLE_ALIAS not set - using presigned packageUrl")

    ota = OTAHandler(
        on_status=on_ota_status,
        health_check_cmd=HEALTH_CHECK_CMD,
        fetcher=ota_fetcher,
    )

    def on_job_message(topic, payload, dup, qos, retain, **kwargs):
        try:
            data = json.loads(payload)
        except Exception:
            log.warning("ignoring unparseable job payload")
            return

        execution = data.get("execution") or data
        job_id = execution.get("jobId")
        if not job_id:
            return

        status = execution.get("status")
        if status in ("SUCCEEDED", "FAILED", "CANCELED", "REJECTED", "REMOVED"):
            return
        if job_id in started_jobs:  # idempotent against redelivery
            return

        document = execution.get("jobDocument") or {}
        if not document:
            log.warning("[Jobs] job %s carries an empty jobDocument", job_id)
            return

        if not ota_lock.acquire(blocking=False):
            log.warning("[Jobs] another OTA is in progress; deferring %s", job_id)
            return
        try:
            started_jobs.add(job_id)
            current_job["id"] = job_id
            log.info("[Jobs] received %s: %s", job_id, document)
            publish_job_update("IN_PROGRESS", {"step": "received"})
            ota.handle_job(document, job_id=job_id)
        except Exception as e:
            log.exception("[Jobs] job %s failed", job_id)
            publish_job_update("FAILED", {"error": str(e)})
        finally:
            ota_lock.release()

    jobs_next_accepted = "$aws/things/%s/jobs/$next/get/accepted" % THING_NAME
    jobs_notify = "$aws/things/%s/jobs/notify-next" % THING_NAME

    def resubscribe():
        mqtt_connection.subscribe(
            topic=jobs_next_accepted,
            qos=mqtt.QoS.AT_LEAST_ONCE,
            callback=on_job_message,
        )
        mqtt_connection.subscribe(
            topic=jobs_notify,
            qos=mqtt.QoS.AT_LEAST_ONCE,
            callback=on_job_message,
        )
        log.debug("subscribed to job topics")

    resume_holder["fn"] = resubscribe
    resubscribe()

    mqtt_connection.publish(
        topic="$aws/things/%s/jobs/$next/get" % THING_NAME,
        payload=json.dumps({}),
        qos=mqtt.QoS.AT_LEAST_ONCE,
    )
    log.info("[Jobs] subscribed and requested the next pending job")

    # -------------------------------------------------
    # Confirm (or reject) an activation that was mid-restart
    # -------------------------------------------------
    pending = guard.read()
    if pending:
        version = str(pending.get("version") or "?")
        job_id = pending.get("jobId") or None
        log.info(
            "unconfirmed activation detected (version=%s, rollback target=%s)",
            version,
            pending.get("previous"),
        )
        # Reaching this line means the process started. Use the handler's own
        # notion of healthy so this agrees with what the OTA flow would decide.
        try:
            healthy = ota._health_check()
        except Exception as e:
            healthy = False
            log.warning("health check raised: %s", e)

        if healthy:
            guard.confirm()
            if job_id:
                publish_job_update(
                    "SUCCEEDED", {"version": version, "step": "confirmed"}, job_id=job_id
                )
            log.info("build %s confirmed healthy", version)
        else:
            log.error(
                "build %s is NOT healthy - reporting FAILED; the boot guard will "
                "roll back after repeated failures",
                version,
            )
            if job_id:
                publish_job_update(
                    "FAILED",
                    {"version": version, "error": "post-restart health check failed"},
                    job_id=job_id,
                )
                time.sleep(2)  # give the publish a chance to flush
            sys.exit(1)

    # -------------------------------------------------
    # Signals
    # -------------------------------------------------
    stop = threading.Event()

    def _handle_signal(signum, _frame):
        log.info("received signal %s - shutting down", signum)
        stop.set()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    # Now we are genuinely ready: connected, subscribed, and any pending
    # activation resolved.
    watchdog = Watchdog(_watchdog_interval())
    watchdog.start()
    sd_notify("STATUS=telemetry loop running")

    # -------------------------------------------------
    # Telemetry loop
    # -------------------------------------------------
    log.info("entering telemetry loop")
    topic = "secure-edge-fleet/telemetry/%s" % THING_NAME
    failures = 0

    while not stop.is_set():
        if restart_requested.is_set():
            log.info("restarting to confirm the new build")
            sd_notify("STATUS=restarting to confirm new build")
            break

        telemetry = {
            "thingName": THING_NAME,
            "status": "online",
            "timestamp": int(time.time()),
        }
        try:
            mqtt_connection.publish(
                topic=topic,
                payload=json.dumps(telemetry),
                qos=mqtt.QoS.AT_LEAST_ONCE,
            )
            failures = 0
            log.info("published telemetry -> %s", topic)
        except Exception as e:
            # The reconnect handlers own reconnecting; this loop's only job is
            # to not die while they do it. Previously this raised and killed
            # the process, taking the Jobs subscriptions with it.
            failures += 1
            log.warning("telemetry publish failed (%d in a row): %s", failures, e)
            stop.wait(min(30 * failures, 300))
            continue

        stop.wait(30)

    watchdog.stop()
    sd_notify("STATUS=stopping")
    try:
        mqtt_connection.disconnect().result()
    except Exception as e:
        log.warning("disconnect failed: %s", e)
    log.info("stopped")


if __name__ == "__main__":
    main()