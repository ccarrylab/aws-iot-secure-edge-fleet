# agent.py — precise patches

I did **not** rewrite `agent.py` wholesale. The fixes below are small, local and
reviewable, and rewriting the AWS SDK interaction blind — without being able to
exercise `awsiot` against a broker — would risk breaking provisioning that
currently works. Each patch is a drop-in replacement for the current block.

---

## H7 — device identity: persist the serial, and stop fetching the trust anchor

`SERIAL_NUMBER = str(uuid.uuid4())[:8]` sits at module level, so a new serial is
generated on every process start. Provisioning is a multi-step network flow: if
it is interrupted between "AWS created the Thing" and "credentials written to
disk", the retry provisions a **second** Thing and the first becomes an orphan
carrying a live certificate. Eight hex characters is also only 32 bits — roughly
a 1% chance of at least one collision at ~9,300 devices.

**Replace** this block:

```python
SERIAL_NUMBER = str(uuid.uuid4())[:8]
THING_NAME = None


def ensure_root_ca():
    if not ROOT_CA.exists():
        print("Downloading Amazon Root CA...")
        import urllib.request
        urllib.request.urlretrieve(
            "https://www.amazontrust.com/repository/AmazonRootCA1.pem",
            ROOT_CA,
        )
        print("Root CA downloaded.")
```

**with:**

```python
import secrets

THING_NAME = None

SERIAL_FILE = CERTS_DIR / "serial"


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

    The old value was regenerated on every process start, so an interrupted
    provisioning left an orphan Thing behind and the retry minted another.
    """
    CERTS_DIR.mkdir(parents=True, exist_ok=True)   # also fixes the first-boot crash
    try:
        existing = SERIAL_FILE.read_text(encoding="utf-8").strip()
        if existing:
            return existing
    except FileNotFoundError:
        pass

    serial = _hardware_serial() or secrets.token_hex(8)
    # O_EXCL: two racing processes can never disagree about the serial.
    fd = os.open(SERIAL_FILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.write(fd, serial.encode())
    finally:
        os.close(fd)
    print(f"Generated device serial: {serial}")
    return serial


def ensure_root_ca():
    """Vendored, not downloaded.

    Fetching the trust anchor over the network you are about to trust, once, on
    a device you may never physically reach again, is a bootstrap you cannot
    audit. Commit AmazonRootCA1.pem (or bake it into the image) and fail loudly
    when it is absent. Also note the OLD version called urlretrieve() without
    creating certs/ first, so a clean checkout raised FileNotFoundError in
    main()'s very first statement.
    """
    if not ROOT_CA.exists():
        raise SystemExit(
            f"Missing {ROOT_CA}. Ship AmazonRootCA1.pem with the agent "
            "instead of downloading it at boot."
        )
```

**Then** thread the serial through instead of reading a global:

```python
    # in main()
    serial = load_or_create_serial()
    ...
    client_id = f"claim-{serial}"
    ...
    provisioner = FleetProvisioner(mqtt_connection, serial=serial)
```

```python
    # FleetProvisioner
    def __init__(self, mqtt_connection, serial: str):
        ...
        self.serial = serial
```

```python
    # and in _on_create_accepted
    register_payload = {
        "certificateOwnershipToken": self.ownership_token,
        "parameters": {"SerialNumber": self.serial},
    }
```

---

## H7b — write the private key at 0600, not 0644-then-chmod

```python
DEVICE_KEY.write_text(key_pem)
...
os.chmod(DEVICE_KEY, 0o600)
```

leaves a window where the private key exists under the process umask —
typically world-readable.

**Replace `save_device_credentials` with:**

```python
def _write_secret(path: Path, data: str) -> None:
    fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data.encode())
        os.fsync(fd)      # a key that vanishes in a power cut means a re-provision
    finally:
        os.close(fd)


def save_device_credentials(cert_pem: str, key_pem: str, thing_name: str):
    CERTS_DIR.mkdir(parents=True, exist_ok=True)
    _write_secret(DEVICE_CERT, cert_pem)
    _write_secret(DEVICE_KEY, key_pem)
    _write_secret(THING_NAME_FILE, thing_name)
    print(f"Saved permanent credentials for thing: {thing_name}")
```

---

## H6 — await the SUBACK, and never let a callback swallow its own failure

`time.sleep(1)` is a guess that the subscription landed. On a slow first TLS
handshake the create-request is published before the accepted-topic
subscription exists, the response goes nowhere, and 90 seconds later you get
`"Provisioning timed out"`. And because the callbacks are unguarded, a
`KeyError` inside one is swallowed by the MQTT thread — so the **real** error is
lost and only the generic timeout is reported.

**Add a helper and use it for every subscription:**

```python
    def _sub(self, topic: str, callback) -> None:
        """Subscribe and WAIT for the SUBACK - no sleep-based guessing."""
        future, _ = self.mqtt.subscribe(
            topic=topic,
            qos=mqtt.QoS.AT_LEAST_ONCE,
            callback=callback,
        )
        future.result(timeout=10)
```

```python
    def start(self):
        self._sub("$aws/certificates/create/json/accepted", self._on_create_accepted)
        self._sub("$aws/certificates/create/json/rejected", self._on_create_rejected)
        provision_base = f"$aws/provisioning-templates/{TEMPLATE_NAME}/provision/json"
        self._sub(f"{provision_base}/accepted", self._on_register_accepted)
        self._sub(f"{provision_base}/rejected", self._on_register_rejected)
        # no time.sleep(1) here
        print("Requesting new device certificate...")
        self.mqtt.publish(...)
```

**Guard every callback body**, and always record the real cause:

```python
    def _on_create_accepted(self, topic, payload, dup, qos, retain, **kwargs):
        try:
            data = json.loads(payload)
            print("Certificate create accepted")
            self.ownership_token = data["certificateOwnershipToken"]
            self.certificate_pem = data["certificatePem"]
            self.private_key = data["privateKey"]
            register_payload = {
                "certificateOwnershipToken": self.ownership_token,
                "parameters": {"SerialNumber": self.serial},
            }
            self.mqtt.publish(
                topic=f"$aws/provisioning-templates/{TEMPLATE_NAME}/provision/json",
                payload=json.dumps(register_payload),
                qos=mqtt.QoS.AT_LEAST_ONCE,
            )
        except Exception as e:
            # Terminal: without the certificate we cannot continue. Surface the
            # real cause instead of a 90-second "Provisioning timed out".
            log.exception("provisioning callback failed")
            self.error = f"Certificate create handling failed: {e!r}"
            self.done = True
```

Apply the same try/except-into-`self.error`/`self.done` shape to
`_on_register_accepted`, `_on_create_rejected` and `_on_register_rejected`.

**Also subscribe to the Jobs rejection topic** — today only `/accepted` is
subscribed, so a rejected "get next job" is silently dropped:

```python
    mqtt_connection.subscribe(
        topic=f"$aws/things/{THING_NAME}/jobs/$next/get/rejected",
        qos=mqtt.QoS.AT_LEAST_ONCE,
        callback=on_job_rejected,     # logs the reason and clears current_job_id
    )
```

---

## H3 — bind the job id to its execution, and serialise OTAs

`current_job_id` is a single mutable slot read at publish time. If
`notify-next` fires for job B while job A is installing, every remaining update
for A — including its terminal `SUCCEEDED`/`FAILED` — is published to **B's**
topic. A then sits `IN_PROGRESS` forever, and `ota.handle_job()` can run twice
concurrently over the same directories.

**Replace the jobs block with:**

```python
    import threading

    ota_lock = threading.Lock()
    started_jobs = set()

    def publish_job_update(job_id: str, status: str, details: dict):
        if not job_id:
            return
        payload = {
            "status": status,
            "statusDetails": {k: str(v) for k, v in details.items()},
        }
        mqtt_connection.publish(
            topic=f"$aws/things/{THING_NAME}/jobs/{job_id}/update",
            payload=json.dumps(payload),
            qos=mqtt.QoS.AT_LEAST_ONCE,
        )
        print(f"[Jobs] Reported {status} for job {job_id}")

    # the job id is bound per execution, never read from a global
    ota = OTAHandler(on_status=lambda status, details: publish_job_update(
        current["job_id"], status, details))
    current = {"job_id": None}

    def on_job_message(topic, payload, dup, qos, retain, **kwargs):
        try:
            data = json.loads(payload)
        except Exception:
            return
        execution = data.get("execution") or data
        job_id = execution.get("jobId")
        document = execution.get("jobDocument") or {}
        if not job_id:
            return
        status = execution.get("status")
        if status in ("SUCCEEDED", "FAILED", "CANCELED", "REJECTED", "REMOVED"):
            return
        if job_id in started_jobs:          # idempotent against redelivery
            return

        if not ota_lock.acquire(blocking=False):
            print(f"[Jobs] Another OTA is in progress; deferring {job_id}")
            return
        try:
            started_jobs.add(job_id)
            current["job_id"] = job_id
            print(f"[Jobs] Received job {job_id}: {document}")
            publish_job_update(job_id, "IN_PROGRESS", {"step": "received"})
            ota.handle_job(document, job_id=job_id)
        finally:
            ota_lock.release()
```

---

## H2 — survive a disconnected publish, re-subscribe on resume, publish a will

`mqtt_connection.publish()` raises while the connection is down, and only
`KeyboardInterrupt` is caught — so the telemetry loop kills the whole process.
That also throws away the Jobs subscriptions and any in-flight OTA state, which
is the opposite of the resilience the README advertises.

**Register a Last Will at connect time** (nothing currently ever publishes a
non-`online` status, so a device that dies mid-heartbeat stays `"status":
"online"` in your telemetry forever):

```python
    will = mqtt.Will(
        topic=f"secure-edge-fleet/telemetry/{client_id}",
        payload=json.dumps({"thingName": client_id, "status": "offline", "timestamp": 0}),
        qos=mqtt.QoS.AT_LEAST_ONCE,
    )

    mqtt_connection = mqtt_connection_builder.mtls_from_path(
        ...
        will=will,
    )
```

**Re-subscribe on resume** (AWS IoT's MQTT 3.1.1 session persistence is limited;
re-subscribing idempotently is the safe pattern):

```python
    def on_connection_resumed(connection, return_code, session_present, **kwargs):
        print(f"Connection resumed. return_code={return_code}, session_present={session_present}")
        if not session_present and resubscribe:
            resubscribe()
```

**And make the telemetry loop survive:**

```python
    print("Entering telemetry loop (Ctrl+C to stop)...")
    failures = 0
    try:
        while True:
            telemetry = {
                "thingName": THING_NAME,
                "status": "online",
                "timestamp": int(time.time()),
            }
            topic = f"secure-edge-fleet/telemetry/{THING_NAME}"
            try:
                mqtt_connection.publish(
                    topic=topic,
                    payload=json.dumps(telemetry),
                    qos=mqtt.QoS.AT_LEAST_ONCE,
                )
                failures = 0
                print(f"Published telemetry -> {topic}")
            except Exception as e:
                # The reconnect handlers own reconnecting; this loop's only job
                # is to not die while they do it.
                failures += 1
                log.warning("telemetry publish failed (%d in a row): %s", failures, e)
                time.sleep(min(30 * failures, 300))
                continue
            time.sleep(30)
    except KeyboardInterrupt:
        print("\nShutting down...")
        mqtt_connection.disconnect().result()
```

---

## While you are in there

- Replace `print()` with the `logging` module (levels, timestamps, and a JSON
  formatter so IoT-shipped logs are parseable). Right now debug output and real
  failures are indistinguishable in journald.
- Handle SIGTERM/SIGINT so `systemctl stop` does not kill the process in the
  middle of an `extract` or an activation.
- Drop the unused `boto3` and `requests` from `requirements.txt` — the code uses
  `urllib.request`, and both are installed on every device for nothing.
- Read `IOT_ENDPOINT` and `TEMPLATE_NAME` from the environment / SSM rather than
  editing source. The committed endpoint
  (`a3m4rx2lnx5xlz-ats.iot.us-east-1.amazonaws.com`) looks like a live,
  account-specific endpoint; have `terraform output` feed the config and never
  ask users to edit a tracked file for configuration.
