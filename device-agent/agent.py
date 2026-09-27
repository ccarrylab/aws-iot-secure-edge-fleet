#!/usr/bin/env python3
"""
Secure Edge Fleet Device Agent
- Fleet Provisioning by Claim (full handshake)
- Switches to permanent device certificate
- Basic telemetry
- Ready for OTA Jobs (next step)
"""

import time
import json
import uuid
import os
import sys
from pathlib import Path

from awsiot import mqtt_connection_builder
from awscrt import mqtt

# -------------------------------------------------
# Configuration
# -------------------------------------------------
IOT_ENDPOINT = "a3m4rx2lnx5xlz-ats.iot.us-east-1.amazonaws.com"
TEMPLATE_NAME = "secure-edge-fleet-prov-template"

CERTS_DIR = Path("certs")
CLAIM_CERT = CERTS_DIR / "claim-certificate.pem"
CLAIM_KEY = CERTS_DIR / "claim-private.key"
ROOT_CA = CERTS_DIR / "AmazonRootCA1.pem"

# After successful provisioning these will be written here
DEVICE_CERT = CERTS_DIR / "device-certificate.pem"
DEVICE_KEY = CERTS_DIR / "device-private.key"
THING_NAME_FILE = CERTS_DIR / "thing_name.txt"

SERIAL_NUMBER = str(uuid.uuid4())[:8]
THING_NAME = None


# -------------------------------------------------
# Helpers
# -------------------------------------------------
def ensure_root_ca():
    if not ROOT_CA.exists():
        print("Downloading Amazon Root CA...")
        import urllib.request
        urllib.request.urlretrieve(
            "https://www.amazontrust.com/repository/AmazonRootCA1.pem",
            ROOT_CA
        )
        print("Root CA downloaded.")


def save_device_credentials(cert_pem: str, key_pem: str, thing_name: str):
    CERTS_DIR.mkdir(exist_ok=True)
    DEVICE_CERT.write_text(cert_pem)
    DEVICE_KEY.write_text(key_pem)
    THING_NAME_FILE.write_text(thing_name)
    # Restrict permissions
    os.chmod(DEVICE_CERT, 0o600)
    os.chmod(DEVICE_KEY, 0o600)
    print(f"Saved permanent credentials for thing: {thing_name}")


def load_existing_thing():
    if DEVICE_CERT.exists() and DEVICE_KEY.exists() and THING_NAME_FILE.exists():
        return THING_NAME_FILE.read_text().strip()
    return None


# -------------------------------------------------
# Callbacks
# -------------------------------------------------
def on_connection_interrupted(connection, error, **kwargs):
    print(f"Connection interrupted: {error}")


def on_connection_resumed(connection, return_code, session_present, **kwargs):
    print(f"Connection resumed. return_code={return_code}, session_present={session_present}")


# -------------------------------------------------
# Fleet Provisioning
# -------------------------------------------------
class FleetProvisioner:
    def __init__(self, mqtt_connection):
        self.mqtt = mqtt_connection
        self.ownership_token = None
        self.certificate_id = None
        self.certificate_pem = None
        self.private_key = None
        self.thing_name = None
        self.done = False
        self.error = None

    def start(self):
        # Subscribe to certificate creation responses
        self.mqtt.subscribe(
            topic="$aws/certificates/create/json/accepted",
            qos=mqtt.QoS.AT_LEAST_ONCE,
            callback=self._on_create_accepted
        )
        self.mqtt.subscribe(
            topic="$aws/certificates/create/json/rejected",
            qos=mqtt.QoS.AT_LEAST_ONCE,
            callback=self._on_create_rejected
        )

        # Subscribe to RegisterThing responses
        provision_base = f"$aws/provisioning-templates/{TEMPLATE_NAME}/provision/json"
        self.mqtt.subscribe(
            topic=f"{provision_base}/accepted",
            qos=mqtt.QoS.AT_LEAST_ONCE,
            callback=self._on_register_accepted
        )
        self.mqtt.subscribe(
            topic=f"{provision_base}/rejected",
            qos=mqtt.QoS.AT_LEAST_ONCE,
            callback=self._on_register_rejected
        )

        time.sleep(1)  # give subscriptions a moment

        print("Requesting new device certificate...")
        self.mqtt.publish(
            topic="$aws/certificates/create/json",
            payload=json.dumps({}),
            qos=mqtt.QoS.AT_LEAST_ONCE
        )

    def _on_create_accepted(self, topic, payload, dup, qos, retain, **kwargs):
        data = json.loads(payload)
        print("Certificate create accepted")
        self.ownership_token = data["certificateOwnershipToken"]
        self.certificate_id = data["certificateId"]
        self.certificate_pem = data["certificatePem"]
        self.private_key = data["privateKey"]

        # Now register the thing
        register_payload = {
            "certificateOwnershipToken": self.ownership_token,
            "parameters": {
                "SerialNumber": SERIAL_NUMBER
            }
        }
        topic = f"$aws/provisioning-templates/{TEMPLATE_NAME}/provision/json"
        print(f"Registering thing with template {TEMPLATE_NAME}...")
        self.mqtt.publish(
            topic=topic,
            payload=json.dumps(register_payload),
            qos=mqtt.QoS.AT_LEAST_ONCE
        )

    def _on_create_rejected(self, topic, payload, dup, qos, retain, **kwargs):
        data = json.loads(payload)
        self.error = f"Certificate create rejected: {data}"
        print(self.error)
        self.done = True

    def _on_register_accepted(self, topic, payload, dup, qos, retain, **kwargs):
        data = json.loads(payload)
        print("RegisterThing accepted")
        self.thing_name = data["thingName"]
        # deviceConfiguration can also appear here if defined in template
        save_device_credentials(
            self.certificate_pem,
            self.private_key,
            self.thing_name
        )
        self.done = True

    def _on_register_rejected(self, topic, payload, dup, qos, retain, **kwargs):
        data = json.loads(payload)
        self.error = f"RegisterThing rejected: {data}"
        print(self.error)
        self.done = True

    def wait(self, timeout=60):
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
    ensure_root_ca()

    # Reuse existing permanent credentials if present
    existing = load_existing_thing()
    if existing:
        print(f"Found existing device credentials for: {existing}")
        THING_NAME = existing
        cert_path = str(DEVICE_CERT)
        key_path = str(DEVICE_KEY)
        client_id = THING_NAME
    else:
        print(f"No permanent credentials found. Starting Fleet Provisioning with serial: {SERIAL_NUMBER}")
        cert_path = str(CLAIM_CERT)
        key_path = str(CLAIM_KEY)
        client_id = f"claim-{SERIAL_NUMBER}"

    mqtt_connection = mqtt_connection_builder.mtls_from_path(
        endpoint=IOT_ENDPOINT,
        cert_filepath=cert_path,
        pri_key_filepath=key_path,
        ca_filepath=str(ROOT_CA),
        client_id=client_id,
        clean_session=False,
        keep_alive_secs=30,
        on_connection_interrupted=on_connection_interrupted,
        on_connection_resumed=on_connection_resumed
    )

    print(f"Connecting as {client_id}...")
    connect_future = mqtt_connection.connect()
    connect_future.result()
    print("Connected!")

    # Run provisioning if needed
    if THING_NAME is None:
        provisioner = FleetProvisioner(mqtt_connection)
        provisioner.start()
        success = provisioner.wait(timeout=90)

        if not success:
            print(f"Provisioning failed: {provisioner.error}")
            mqtt_connection.disconnect().result()
            sys.exit(1)

        THING_NAME = provisioner.thing_name
        print(f"Provisioning complete. Thing name: {THING_NAME}")

        # Disconnect claim connection and reconnect with permanent cert
        print("Switching to permanent device certificate...")
        mqtt_connection.disconnect().result()

        mqtt_connection = mqtt_connection_builder.mtls_from_path(
            endpoint=IOT_ENDPOINT,
            cert_filepath=str(DEVICE_CERT),
            pri_key_filepath=str(DEVICE_KEY),
            ca_filepath=str(ROOT_CA),
            client_id=THING_NAME,
            clean_session=False,
            keep_alive_secs=30,
            on_connection_interrupted=on_connection_interrupted,
            on_connection_resumed=on_connection_resumed
        )
        mqtt_connection.connect().result()
        print("Reconnected with permanent credentials.")

    # Telemetry loop
    print("Entering telemetry loop (Ctrl+C to stop)...")
    try:
        while True:
            telemetry = {
                "serial": SERIAL_NUMBER if THING_NAME is None else THING_NAME,
                "thingName": THING_NAME,
                "status": "online",
                "timestamp": int(time.time())
            }
            topic = f"secure-edge-fleet/telemetry/{THING_NAME}"
            mqtt_connection.publish(
                topic=topic,
                payload=json.dumps(telemetry),
                qos=mqtt.QoS.AT_LEAST_ONCE
            )
            print(f"Published telemetry → {topic}")
            time.sleep(30)
    except KeyboardInterrupt:
        print("\nShutting down...")
        mqtt_connection.disconnect().result()


if __name__ == "__main__":
    main()