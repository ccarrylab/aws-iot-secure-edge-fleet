"""Tests for device-agent/agent.py. The AWS IoT SDK is mocked; nothing touches the network."""
import json
import logging
import os
import shutil
import signal
import socket
import stat
import sys
import tempfile
import time
import types
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

AGENT_DIR = Path(__file__).resolve().parent.parent
if str(AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(AGENT_DIR))

try:
    import awsiot  # noqa: F401
    import awscrt  # noqa: F401
except ImportError:  # SDK not installed: minimal stand-ins so agent.py imports
    class _QoS:
        AT_LEAST_ONCE = 1

    class _Will:
        def __init__(self, topic, qos, payload, retain=False):
            self.topic, self.qos, self.payload, self.retain = topic, qos, payload, retain

    _awscrt = types.ModuleType("awscrt")
    _awscrt.mqtt = SimpleNamespace(QoS=_QoS, Will=_Will)
    _awsiot = types.ModuleType("awsiot")
    _awsiot.mqtt_connection_builder = SimpleNamespace(mtls_from_path=lambda **kw: None)
    sys.modules["awscrt"] = _awscrt
    sys.modules["awsiot"] = _awsiot

import agent  # noqa: E402

THING = "thing-1"


# ------------------------------------------------------------------ fixtures
@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in ("NOTIFY_SOCKET", "WATCHDOG_USEC", "OTA_STATE_DIR"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def certs(tmp_path, monkeypatch):
    d = tmp_path / "certs"
    monkeypatch.setattr(agent, "CERTS_DIR", d)
    for attr, name in {
        "CLAIM_CERT": "claim-certificate.pem",
        "CLAIM_KEY": "claim-private.key",
        "ROOT_CA": "AmazonRootCA1.pem",
        "DEVICE_CERT": "device-certificate.pem",
        "DEVICE_KEY": "device-private.key",
        "THING_NAME_FILE": "thing_name.txt",
        "SERIAL_FILE": "serial",
    }.items():
        monkeypatch.setattr(agent, attr, d / name)
    return d


# ------------------------------------------------------------------ logging
def test_json_formatter_emits_parseable_lines():
    rec = logging.LogRecord("agent", logging.INFO, __file__, 1, "hello %s", ("x",), None)
    out = json.loads(agent._JsonFormatter().format(rec))
    assert out["msg"] == "hello x"
    assert out["level"] == "INFO"


# ------------------------------------------------------------------ systemd
def test_sd_notify_is_noop_without_socket():
    assert agent.sd_notify("READY=1") is False


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="needs unix sockets")
def test_sd_notify_delivers_datagram(monkeypatch):
    tmpdir = tempfile.mkdtemp(dir="/tmp")  # short path: AF_UNIX limit on macOS
    path = os.path.join(tmpdir, "notify.sock")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        server.bind(path)
        server.settimeout(2)
        monkeypatch.setenv("NOTIFY_SOCKET", path)
        assert agent.sd_notify("READY=1") is True
        assert server.recv(64) == b"READY=1"
    finally:
        server.close()
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_sd_notify_swallows_errors(monkeypatch):
    monkeypatch.setenv("NOTIFY_SOCKET", "/nonexistent/dir/notify.sock")
    assert agent.sd_notify("READY=1") is False


def test_watchdog_interval(monkeypatch):
    assert agent._watchdog_interval() == 0.0
    monkeypatch.setenv("WATCHDOG_USEC", "30000000")
    assert agent._watchdog_interval() == 15.0
    monkeypatch.setenv("WATCHDOG_USEC", "1000000")
    assert agent._watchdog_interval() == 2.0  # floor
    monkeypatch.setenv("WATCHDOG_USEC", "garbage")
    assert agent._watchdog_interval() == 0.0


def test_watchdog_sends_ready_then_keepalives(monkeypatch):
    sent = []
    monkeypatch.setattr(agent, "sd_notify", lambda m: sent.append(m) or True)
    monkeypatch.setenv("NOTIFY_SOCKET", "/unused")
    wd = agent.Watchdog(0.01)
    wd.start()
    time.sleep(0.15)
    wd.stop()
    wd._thread.join(timeout=1)
    assert sent[0] == "READY=1"
    assert "WATCHDOG=1" in sent


def test_watchdog_inactive_without_interval_or_socket(monkeypatch):
    sent = []
    monkeypatch.setattr(agent, "sd_notify", lambda m: sent.append(m) or True)
    monkeypatch.setenv("NOTIFY_SOCKET", "/unused")
    wd = agent.Watchdog(0.0)
    wd.start()
    assert wd._thread is None and sent == []
    monkeypatch.delenv("NOTIFY_SOCKET")
    wd = agent.Watchdog(5.0)
    wd.start()
    assert wd._thread is None and sent == []


# ------------------------------------------------------------------ boot guard
def test_boot_guard_arm_read_confirm(tmp_path):
    guard = agent.BootGuard(tmp_path / "state")
    assert guard.read() is None

    guard.arm(previous="1.1.0", job_id="job-1", version="1.2.0")
    assert guard.pending.read_text() == "1.1.0"  # exact format the shell guard reads
    assert guard.read() == {"previous": "1.1.0", "jobId": "job-1", "version": "1.2.0"}

    guard.confirm()
    assert guard.read() is None
    assert not guard.meta.exists() and not guard.boot_count.exists()


def test_boot_guard_arm_resets_stale_boot_count(tmp_path):
    guard = agent.BootGuard(tmp_path)
    guard.boot_count.write_text("2")
    guard.arm("1.1.0", "job-1", "1.2.0")
    assert not guard.boot_count.exists()


def test_boot_guard_tolerates_corrupt_meta(tmp_path):
    guard = agent.BootGuard(tmp_path)
    guard.pending.write_text("1.1.0")
    guard.meta.write_text("{not json")
    assert guard.read() == {"previous": "1.1.0"}


def test_boot_guard_confirm_is_idempotent(tmp_path):
    guard = agent.BootGuard(tmp_path)
    guard.confirm()
    guard.confirm()


# ------------------------------------------------------------------ state dir
def test_resolve_state_dir_prefers_env(tmp_path, monkeypatch):
    target = tmp_path / "state"
    monkeypatch.setenv("OTA_STATE_DIR", str(target))
    assert agent.resolve_state_dir() == target and target.is_dir()


def test_resolve_state_dir_falls_back_when_unwritable(tmp_path, monkeypatch):
    blocker = tmp_path / "blocker"
    blocker.write_text("a file, so mkdir beneath it fails")
    fallback = tmp_path / "fallback"
    monkeypatch.setenv("OTA_STATE_DIR", str(blocker / "sub"))
    monkeypatch.setattr(agent, "STATE_DIR_DEFAULT", str(fallback))
    assert agent.resolve_state_dir() == fallback


# ------------------------------------------------------------------ identity
def test_serial_is_created_once_and_persisted(certs, monkeypatch):
    monkeypatch.setattr(agent, "_hardware_serial", lambda: None)
    first = agent.load_or_create_serial()
    assert len(first) == 16
    assert agent.load_or_create_serial() == first
    assert stat.S_IMODE(agent.SERIAL_FILE.stat().st_mode) == 0o600


def test_serial_prefers_hardware_id(certs, monkeypatch):
    monkeypatch.setattr(agent, "_hardware_serial", lambda: "HW-1234")
    assert agent.load_or_create_serial() == "HW-1234"


def test_existing_serial_is_honored(certs):
    certs.mkdir(parents=True)
    agent.SERIAL_FILE.write_text("preset\n")
    assert agent.load_or_create_serial() == "preset"


def test_empty_serial_file_is_repaired(certs, monkeypatch):
    monkeypatch.setattr(agent, "_hardware_serial", lambda: None)
    certs.mkdir(parents=True)
    agent.SERIAL_FILE.write_text("")
    assert agent.load_or_create_serial() != ""


def test_write_secret_is_0600_even_with_permissive_umask(tmp_path):
    old = os.umask(0)
    try:
        target = tmp_path / "key"
        agent._write_secret(target, "secret")
    finally:
        os.umask(old)
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert target.read_text() == "secret"


def test_save_and_load_device_credentials(certs):
    assert agent.load_existing_thing() is None
    agent.save_device_credentials("CERT", "KEY", THING)
    assert agent.load_existing_thing() == THING
    assert agent.DEVICE_KEY.read_text() == "KEY"
    assert stat.S_IMODE(agent.DEVICE_KEY.stat().st_mode) == 0o600


def test_partial_credentials_are_not_an_identity(certs):
    certs.mkdir(parents=True)
    agent.DEVICE_CERT.write_text("x")
    agent.DEVICE_KEY.write_text("y")  # thing_name.txt missing
    assert agent.load_existing_thing() is None


def test_ensure_root_ca(certs):
    with pytest.raises(SystemExit) as exc:
        agent.ensure_root_ca()
    assert "AmazonRootCA1.pem" in str(exc.value)
    certs.mkdir(parents=True)
    agent.ROOT_CA.write_text("pem")
    agent.ensure_root_ca()


# ------------------------------------------------------------------ connection
@pytest.fixture
def builder(certs, monkeypatch):
    captured = {}

    class FakeWill:
        def __init__(self, topic, qos, payload, retain=False):
            self.topic, self.qos, self.payload = topic, qos, payload

    monkeypatch.setattr(agent.mqtt, "Will", FakeWill)
    monkeypatch.setattr(
        agent.mqtt_connection_builder,
        "mtls_from_path",
        lambda **kw: captured.update(kw) or "conn",
    )
    return captured


def test_build_connection_registers_offline_will(builder):
    conn = agent.build_connection(
        "dev-1", agent.DEVICE_CERT, agent.DEVICE_KEY, clean_session=False
    )
    assert conn == "conn"
    assert builder["client_id"] == "dev-1"
    assert builder["clean_session"] is False
    assert builder["keep_alive_secs"] == 30
    will = builder["will"]
    assert will.topic == "secure-edge-fleet/telemetry/dev-1"
    assert json.loads(will.payload)["status"] == "offline"


def test_resume_callback_resubscribes_only_when_session_lost(builder):
    resumed = []
    agent.build_connection(
        "dev-1", agent.DEVICE_CERT, agent.DEVICE_KEY, False,
        on_resume=lambda: resumed.append(1),
    )
    cb = builder["on_connection_resumed"]
    cb(None, 0, True)
    assert resumed == []
    cb(None, 0, False)
    assert resumed == [1]


def test_resume_callback_swallows_resubscribe_errors(builder):
    def boom():
        raise RuntimeError("nope")

    agent.build_connection(
        "dev-1", agent.DEVICE_CERT, agent.DEVICE_KEY, False, on_resume=boom
    )
    builder["on_connection_resumed"](None, 0, False)  # must not raise


# ------------------------------------------------------------------ provisioning
def _payload(d):
    return json.dumps(d).encode()


def _prov(serial="abc"):
    m = MagicMock()
    future = MagicMock()
    m.subscribe.return_value = (future, 1)
    return agent.FleetProvisioner(m, serial=serial), m, future


def _call(cb, payload):
    cb("topic", payload, False, 1, False)


def test_provisioner_subscribes_and_waits_for_suback_before_publishing():
    prov, m, future = _prov()
    prov.start()
    topics = {c.kwargs["topic"] for c in m.subscribe.call_args_list}
    base = "$aws/provisioning-templates/%s/provision/json" % agent.TEMPLATE_NAME
    assert topics == {
        "$aws/certificates/create/json/accepted",
        "$aws/certificates/create/json/rejected",
        base + "/accepted",
        base + "/rejected",
    }
    assert future.result.call_count == 4  # every SUBACK awaited
    assert m.publish.call_args.kwargs["topic"] == "$aws/certificates/create/json"


def test_full_provisioning_flow(certs):
    prov, m, _ = _prov(serial="abc")
    _call(prov._on_create_accepted, _payload(
        {"certificateOwnershipToken": "tok", "certificatePem": "CERT", "privateKey": "KEY"}
    ))
    sent = m.publish.call_args.kwargs
    assert agent.TEMPLATE_NAME in sent["topic"]
    assert json.loads(sent["payload"]) == {
        "certificateOwnershipToken": "tok",
        "parameters": {"SerialNumber": "abc"},
    }
    _call(prov._on_register_accepted, _payload({"thingName": THING}))
    assert prov.wait(timeout=1) is True
    assert prov.thing_name == THING
    assert agent.load_existing_thing() == THING


def test_malformed_create_response_fails_fast_not_by_timeout():
    prov, _, _ = _prov()
    _call(prov._on_create_accepted, _payload({"certificatePem": "CERT"}))  # no token
    assert prov.done and "callback failed" in prov.error
    assert prov.wait(timeout=1) is False


def test_rejections_are_reported():
    prov, _, _ = _prov()
    _call(prov._on_create_rejected, _payload({"errorCode": "Denied"}))
    assert "rejected" in prov.error and prov.done

    prov, _, _ = _prov()
    _call(prov._on_register_rejected, b"not json")
    assert "rejected" in prov.error and prov.done


def test_provisioning_timeout():
    prov, _, _ = _prov()
    assert prov.wait(timeout=0) is False
    assert prov.error == "Provisioning timed out"


# ------------------------------------------------------------------ main(): harness
class _Done:
    def result(self, timeout=None):
        return None


class FakeConnection:
    """Stands in for an mqtt connection. On the first telemetry publish it delivers
    the configured job (if any), then signals shutdown so main() returns."""

    def __init__(self, stop):
        self._stop = stop
        self.callbacks = {}
        self.published = []
        self.disconnected = False
        self.job = None
        self.job_status = "QUEUED"
        self.deliveries = 1
        self.redeliver_on_get = False
        self.telemetry_error = None
        self._telemetry_calls = 0

    def connect(self):
        return _Done()

    def disconnect(self):
        self.disconnected = True
        return _Done()

    def subscribe(self, topic, qos, callback):
        self.callbacks[topic] = callback
        return _Done(), 1

    def _deliver(self):
        cb = self.callbacks["$aws/things/%s/jobs/$next/get/accepted" % THING]
        body = {"execution": {"jobId": "job-1", "status": self.job_status,
                              "jobDocument": self.job}}
        cb("t", json.dumps(body).encode(), False, 1, False)

    def publish(self, topic, payload, qos):
        self.published.append((topic, json.loads(payload)))
        if topic.endswith("/jobs/$next/get") and self.redeliver_on_get:
            self._deliver()
        if topic.startswith("secure-edge-fleet/telemetry/"):
            self._telemetry_calls += 1
            if self._telemetry_calls == 1 and self.job is not None and not self.redeliver_on_get:
                for _ in range(self.deliveries):
                    self._deliver()
            self._stop()
            if self.telemetry_error:
                raise self.telemetry_error
        return _Done(), 1


def make_fake_ota(healthy=True, on_handle=None):
    class FakeOTA:
        instances = []

        def __init__(self, on_status=None, health_check_cmd=None, fetcher=None, **kw):
            self.on_status = on_status
            self.fetcher = fetcher
            self.handled = []
            FakeOTA.instances.append(self)

        def _health_check(self):
            return healthy

        def handle_job(self, document, job_id=None):
            self.handled.append((document, job_id))
            if on_handle:
                on_handle(self, document, job_id)

    return FakeOTA


def job_updates(conn, job_id):
    suffix = "/jobs/%s/update" % job_id
    return [body for topic, body in conn.published if topic.endswith(suffix)]


@pytest.fixture
def env(monkeypatch, tmp_path, certs):
    handlers = {}
    monkeypatch.setattr(agent.signal, "signal", lambda s, f: handlers.__setitem__(s, f))
    conn = FakeConnection(lambda: handlers[signal.SIGTERM](signal.SIGTERM, None))
    state = tmp_path / "state"
    monkeypatch.setenv("OTA_STATE_DIR", str(state))
    monkeypatch.setenv("IOT_ENDPOINT", "example-ats.iot.us-east-1.amazonaws.com")
    monkeypatch.setattr(agent, "_setup_logging", lambda: None)
    monkeypatch.setattr(agent, "ensure_root_ca", lambda: None)
    monkeypatch.setattr(agent, "load_existing_thing", lambda: THING)
    monkeypatch.setattr(agent, "ROLE_ALIAS", "")
    monkeypatch.setattr(agent, "build_connection", lambda *a, **k: conn)
    monkeypatch.setattr(agent.time, "sleep", lambda s: None)
    monkeypatch.setattr(agent, "OTAHandler", make_fake_ota())
    return SimpleNamespace(conn=conn, state=state)


# ------------------------------------------------------------------ main(): OTA + rollback
def test_activation_defers_succeeded_and_arms_boot_guard(env, monkeypatch):
    def activate(ota, doc, job_id):
        ota.on_status("SUCCEEDED", {"previous": "1.1.0", "version": "1.2.0"})

    monkeypatch.setattr(agent, "OTAHandler", make_fake_ota(on_handle=activate))
    env.conn.job = {"version": "1.2.0"}

    agent.main()

    statuses = [b["status"] for b in job_updates(env.conn, "job-1")]
    assert "SUCCEEDED" not in statuses  # not until the new build has booted
    assert statuses == ["IN_PROGRESS", "IN_PROGRESS"]
    assert (env.state / "pending").read_text() == "1.1.0"
    assert json.loads((env.state / "pending.json").read_text()) == {
        "previous": "1.1.0", "jobId": "job-1", "version": "1.2.0",
    }
    assert env.conn.disconnected


def test_success_without_previous_is_passed_through(env, monkeypatch):
    monkeypatch.setattr(agent, "OTAHandler", make_fake_ota(
        on_handle=lambda o, d, j: o.on_status("SUCCEEDED", {"version": "1.2.0"})))
    env.conn.job = {"version": "1.2.0"}
    agent.main()
    assert [b["status"] for b in job_updates(env.conn, "job-1")] == ["IN_PROGRESS", "SUCCEEDED"]
    assert not (env.state / "pending").exists()


def test_failed_ota_is_reported(env, monkeypatch):
    monkeypatch.setattr(agent, "OTAHandler", make_fake_ota(
        on_handle=lambda o, d, j: o.on_status("FAILED", {"error": "bad checksum"})))
    env.conn.job = {"version": "1.2.0"}
    agent.main()
    updates = job_updates(env.conn, "job-1")
    assert updates[-1] == {"status": "FAILED", "statusDetails": {"error": "bad checksum"}}


def test_handler_exception_becomes_failed_job(env, monkeypatch):
    def boom(ota, doc, job_id):
        raise RuntimeError("boom")

    monkeypatch.setattr(agent, "OTAHandler", make_fake_ota(on_handle=boom))
    env.conn.job = {"version": "1.2.0"}
    agent.main()
    last = job_updates(env.conn, "job-1")[-1]
    assert last["status"] == "FAILED" and "boom" in last["statusDetails"]["error"]


def test_redelivered_job_runs_once(env, monkeypatch):
    fake = make_fake_ota(on_handle=lambda o, d, j: o.on_status("FAILED", {"error": "x"}))
    monkeypatch.setattr(agent, "OTAHandler", fake)
    env.conn.job = {"version": "1.2.0"}
    env.conn.deliveries = 2
    agent.main()
    assert len(fake.instances[0].handled) == 1


def test_terminal_and_empty_jobs_are_ignored(env, monkeypatch):
    fake = make_fake_ota()
    monkeypatch.setattr(agent, "OTAHandler", fake)
    env.conn.job = {"version": "1.2.0"}
    env.conn.job_status = "SUCCEEDED"
    agent.main()
    assert fake.instances[0].handled == [] and job_updates(env.conn, "job-1") == []


def test_empty_job_document_is_ignored(env, monkeypatch):
    fake = make_fake_ota()
    monkeypatch.setattr(agent, "OTAHandler", fake)
    env.conn.job = {}
    agent.main()
    assert fake.instances[0].handled == []


def test_startup_confirms_healthy_build_and_reports_succeeded(env, monkeypatch):
    agent.BootGuard(env.state).arm("1.1.0", "job-9", "1.2.0")
    monkeypatch.setattr(agent, "OTAHandler", make_fake_ota(healthy=True))
    agent.main()
    assert not (env.state / "pending").exists()
    assert job_updates(env.conn, "job-9") == [
        {"status": "SUCCEEDED", "statusDetails": {"version": "1.2.0", "step": "confirmed"}}
    ]


def test_startup_unhealthy_build_reports_failed_and_leaves_guard_armed(env, monkeypatch):
    agent.BootGuard(env.state).arm("1.1.0", "job-9", "1.2.0")
    monkeypatch.setattr(agent, "OTAHandler", make_fake_ota(healthy=False))
    with pytest.raises(SystemExit) as exc:
        agent.main()
    assert exc.value.code == 1
    assert job_updates(env.conn, "job-9")[-1]["status"] == "FAILED"
    assert (env.state / "pending").exists()  # the shell guard needs this to roll back


# ------------------------------------------------------------------ main(): credential provider
def test_role_alias_wires_credential_provider_fetcher(env, monkeypatch):
    calls, sentinel = {}, object()
    mod = types.ModuleType("s3_fetch")
    mod.make_fetcher = lambda **kw: calls.update(kw) or sentinel
    monkeypatch.setitem(sys.modules, "s3_fetch", mod)
    monkeypatch.setattr(agent, "ROLE_ALIAS", "my-alias")
    fake = make_fake_ota()
    monkeypatch.setattr(agent, "OTAHandler", fake)
    agent.main()
    assert calls["role_alias"] == "my-alias"
    assert calls["thing_name"] == THING
    assert calls["max_bytes"] == agent.MAX_DOWNLOAD_BYTES
    assert fake.instances[0].fetcher is sentinel


def test_fetcher_build_failure_falls_back_to_presigned_urls(env, monkeypatch):
    def broken(**kw):
        raise RuntimeError("no creds")

    mod = types.ModuleType("s3_fetch")
    mod.make_fetcher = broken
    monkeypatch.setitem(sys.modules, "s3_fetch", mod)
    monkeypatch.setattr(agent, "ROLE_ALIAS", "my-alias")
    fake = make_fake_ota()
    monkeypatch.setattr(agent, "OTAHandler", fake)
    agent.main()
    assert fake.instances[0].fetcher is None


def test_no_role_alias_means_no_fetcher(env, monkeypatch):
    fake = make_fake_ota()
    monkeypatch.setattr(agent, "OTAHandler", fake)
    agent.main()
    assert fake.instances[0].fetcher is None


# ------------------------------------------------------------------ main(): resilience + provisioning
def test_telemetry_failure_does_not_kill_the_agent(env):
    env.conn.telemetry_error = RuntimeError("net down")
    agent.main()  # must return normally
    assert env.conn.disconnected


def _fake_provisioner(ok):
    class FakeProvisioner:
        def __init__(self, conn, serial):
            self.thing_name = THING
            self.error = None if ok else "boom"

        def start(self):
            pass

        def wait(self):
            return ok

    return FakeProvisioner


def test_first_boot_provisions_then_reconnects_as_thing(env, monkeypatch):
    ids = []
    monkeypatch.setattr(agent, "load_existing_thing", lambda: None)
    monkeypatch.setattr(agent, "load_or_create_serial", lambda: "abc")
    monkeypatch.setattr(agent, "FleetProvisioner", _fake_provisioner(True))
    monkeypatch.setattr(agent, "build_connection",
                        lambda client_id, *a, **k: ids.append(client_id) or env.conn)
    agent.main()
    assert ids == ["claim-abc", THING]


def test_provisioning_failure_exits_nonzero(env, monkeypatch):
    monkeypatch.setattr(agent, "load_existing_thing", lambda: None)
    monkeypatch.setattr(agent, "load_or_create_serial", lambda: "abc")
    monkeypatch.setattr(agent, "FleetProvisioner", _fake_provisioner(False))
    with pytest.raises(SystemExit) as exc:
        agent.main()
    assert exc.value.code == 1
    assert env.conn.disconnected


def test_job_redelivered_mid_confirmation_is_not_rerun(env, monkeypatch):
    """After a restart AWS hands back the still-IN_PROGRESS job. Re-running it
    would report FAILED ("already installed") and race the real SUCCEEDED."""
    agent.BootGuard(env.state).arm("1.1.0", "job-1", "1.2.0")
    fake = make_fake_ota(healthy=True)
    monkeypatch.setattr(agent, "OTAHandler", fake)
    env.conn.job = {"version": "1.2.0"}
    env.conn.job_status = "IN_PROGRESS"
    env.conn.redeliver_on_get = True
    agent.main()
    assert fake.instances[0].handled == []
    assert [b["status"] for b in job_updates(env.conn, "job-1")] == ["SUCCEEDED"]
