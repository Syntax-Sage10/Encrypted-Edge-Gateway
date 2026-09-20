"""
secure_server.py  —  THE DESTINATION
====================================
Simulates the modern hospital system that receives encrypted telemetry.

For each gateway connection it:
  1. Reads one Fernet token per line.
  2. Verifies + decrypts it with the shared key (tampered or wrong-key tokens are REJECTED).
  3. Re-assembles the original plaintext byte stream.
  4. Splits that stream on "\n" to recover the device's JSON readings and prints them.
"""

import asyncio
import json
import os
import signal
import sys

from cryptography.fernet import Fernet, InvalidToken

LISTEN_HOST, LISTEN_PORT = "127.0.0.1", 9001
KEY_FILE = "fernet.key"
TOKEN_MAX_AGE_SECONDS = 30   # reject tokens older than this (limits replay of captured traffic)
MAX_LINE_BYTES = 1_000_000   # safety cap so a malicious peer can't make us buffer forever


def load_or_create_key(path: str = KEY_FILE) -> bytes:
    """Same atomic create-or-load logic as the gateway (see edge_gateway.py for the explanation)."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        key = Fernet.generate_key()
        with os.fdopen(fd, "wb") as f:
            f.write(key)
        print(f"[SERVER] Generated new shared key -> {path}")
        return key
    except FileExistsError:
        with open(path, "rb") as f:
            key = f.read().strip()
        print(f"[SERVER] Loaded shared key from {path}")
        return key


def print_reading(reading: dict) -> None:
    """Render one decrypted vital-signs record nicely for the demo and save it for the web dashboard."""
    print(
        f"[SERVER] ✔ DECRYPTED #{reading.get('seq')}  {reading.get('timestamp')}  "
        f"patient={reading.get('patient_id')}  HR={reading.get('heart_rate_bpm')} bpm  "
        f"BP={reading.get('blood_pressure')}  SpO2={reading.get('spo2_percent')}%  "
        f"RR={reading.get('resp_rate')}  T={reading.get('temp_c')}°C"
    )
    
    # Save the latest reading to a JSON file for the website to read
    with open("live_data.json", "w") as f:
        json.dump(reading, f)


async def handle_gateway(fernet: Fernet, reader: asyncio.StreamReader,
                         writer: asyncio.StreamWriter) -> None:
    peer = "%s:%s" % writer.get_extra_info("peername")[:2]
    print(f"[SERVER] Gateway connected from {peer}")
    plaintext_buffer = b""   # holds partial device messages until their "\n" arrives

    try:
        while True:
            line = await reader.readline()      # one encrypted token (non-blocking wait)
            if not line:                        # EOF: gateway disconnected
                break
            token = line.strip()
            if not token:
                continue

            print(f"[SERVER] Received ciphertext: {token[:50].decode(errors='replace')}...")

            try:
                # decrypt() checks the HMAC FIRST. If even one bit was altered in
                # transit, or the wrong key was used, it raises InvalidToken and
                # we never touch the (untrusted) data. ttl= also rejects stale tokens.
                chunk = fernet.decrypt(token, ttl=TOKEN_MAX_AGE_SECONDS)
            except InvalidToken:
                print("[SERVER] ✘ REJECTED token: tampered, wrong key, or too old.")
                continue

            # Re-assemble the device's original byte stream, then cut it into messages.
            plaintext_buffer += chunk
            while b"\n" in plaintext_buffer:
                raw, plaintext_buffer = plaintext_buffer.split(b"\n", 1)
                if not raw.strip():
                    continue
                try:
                    print_reading(json.loads(raw))
                except json.JSONDecodeError:
                    print(f"[SERVER] Non-JSON payload: {raw[:80]!r}")
    except (asyncio.LimitOverrunError, ValueError):
        print(f"[SERVER] Oversized line from {peer}; dropping connection.")
    except ConnectionError as e:
        print(f"[SERVER] Connection error from {peer}: {e}")
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        print(f"[SERVER] Gateway {peer} disconnected.")

async def main() -> None:
    fernet = Fernet(load_or_create_key())

    try:
        server = await asyncio.start_server(
            lambda r, w: handle_gateway(fernet, r, w),
            LISTEN_HOST, LISTEN_PORT, limit=MAX_LINE_BYTES,
        )
    except OSError as e:
        print(f"[SERVER] Cannot listen on {LISTEN_HOST}:{LISTEN_PORT}: {e}")
        sys.exit(1)

    print(f"[SERVER] Hospital database listening on {LISTEN_HOST}:{LISTEN_PORT} (encrypted only)")

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except (NotImplementedError, RuntimeError):
            pass

    async with server:
        await stop.wait()
    print("\n[SERVER] Shutting down.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down.")