"""
legacy_machine.py  —  THE VULNERABILITY
=======================================
Simulates a 15-year-old bedside patient monitor that only knows how to do one
thing: open a plain TCP socket and shout readings in cleartext.

It has NO idea the Encrypted Edge Gateway exists. It simply believes it is
talking to "the hospital system" at localhost:9000. That is the whole point:
the legacy device is never modified — the protection is added around it.

Wire format: one JSON object per line ("newline-delimited JSON" / NDJSON).
The trailing "\n" is how the receiver knows where one reading ends and the
next begins, because TCP itself has no concept of "messages" — it is just a
continuous stream of bytes.
"""

import json
import random
import socket
import time
from datetime import datetime, timezone

GATEWAY_HOST = "127.0.0.1"
GATEWAY_PORT = 9000
SEND_INTERVAL_SECONDS = 2
DEVICE_ID = "MON-ICU-07"           # the physical monitor's asset tag
PATIENT_ID = "PT-448213"           # dummy patient — never use real data


def generate_reading(seq: int) -> dict:
    """Produce one realistic-looking vital-signs sample."""
    # Small random walk around normal adult ranges so the numbers look alive.
    return {
        "seq": seq,                                            # sequence number (helps spot lost/duplicated messages)
        "device_id": DEVICE_ID,
        "patient_id": PATIENT_ID,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "heart_rate_bpm": random.randint(62, 98),
        "blood_pressure": f"{random.randint(110, 135)}/{random.randint(70, 88)}",
        "spo2_percent": random.randint(95, 100),
        "resp_rate": random.randint(12, 20),
        "temp_c": round(random.uniform(36.4, 37.6), 1),
    }


def connect_with_retry() -> socket.socket:
    """
    Keep trying to reach the gateway. Old devices in the real world behave
    exactly like this: they retry forever and never give up.
    """
    while True:
        try:
            sock = socket.create_connection((GATEWAY_HOST, GATEWAY_PORT), timeout=5)
            print(f"[LEGACY] Connected to {GATEWAY_HOST}:{GATEWAY_PORT} (believes this is the hospital server)")
            return sock
        except OSError as e:
            print(f"[LEGACY] Cannot reach {GATEWAY_HOST}:{GATEWAY_PORT} ({e}). Retrying in 3s...")
            time.sleep(3)


def main() -> None:
    seq = 0
    sock = connect_with_retry()

    while True:
        reading = generate_reading(seq)
        # Serialize to JSON, add the newline delimiter, convert text -> bytes.
        payload = (json.dumps(reading) + "\n").encode("utf-8")

        try:
            sock.sendall(payload)   # PLAINTEXT on the wire. Anyone sniffing port 9000 can read this.
            print(f"[LEGACY] Sent PLAINTEXT  -> {payload.decode().strip()}")
            seq += 1
        except OSError as e:
            # Gateway went away (crashed, restarted, cable pulled...). Reconnect.
            print(f"[LEGACY] Connection lost ({e}). Reconnecting...")
            sock.close()
            sock = connect_with_retry()
            continue

        time.sleep(SEND_INTERVAL_SECONDS)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[LEGACY] Device powered off.")