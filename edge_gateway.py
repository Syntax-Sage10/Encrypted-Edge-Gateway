"""
edge_gateway.py  —  THE PRODUCT: Encrypted Edge Gateway
=======================================================
An asynchronous, encrypting TCP proxy.

    legacy_machine ──plaintext──▶ [ :9000  EDGE GATEWAY ] ──ciphertext──▶ :9001 secure_server

For every device that connects on port 9000, the gateway:
  1. Opens its own upstream connection to the secure server on port 9001.
  2. Reads whatever raw bytes the device sends (it does NOT need to understand them).
  3. Encrypts each chunk with Fernet.
  4. Forwards the encrypted chunk upstream, one token per line.

HOW THE ENCRYPTION WORKS (what to tell the judges, accurately):
  Fernet is a well-reviewed "recipe" from the `cryptography` library. Each token is:
      version | timestamp | random 128-bit IV | AES-128-CBC ciphertext | HMAC-SHA256 tag
  - AES-128 in CBC mode provides CONFIDENTIALITY (nobody can read it).
  - HMAC-SHA256 provides INTEGRITY + AUTHENTICITY (nobody can alter it undetected;
    a single flipped bit makes decryption fail loudly).
  - A fresh random IV per token means encrypting the same reading twice
    produces completely different ciphertext.
  NOTE: Fernet is AES-128, not AES-256. Do not claim AES-256 for this prototype.

WHY FRAMING MATTERS:
  TCP is a byte stream, not a message stream. One device "message" may arrive
  split across two reads, or two messages may arrive in one read. We therefore
  encrypt whatever chunk we got and put a "\n" after each token. Fernet tokens are
  URL-safe base64, which never contains "\n", so the newline is an unambiguous
  delimiter. The server decrypts each token and re-assembles the original
  plaintext stream byte-for-byte. The gateway is protocol-agnostic: it would
  work unchanged for HL7, DICOM, Modbus, or any other TCP protocol.
"""

import asyncio
import os
import signal
import sys

from cryptography.fernet import Fernet

LISTEN_HOST, LISTEN_PORT = "127.0.0.1", 9000       # where the legacy device sends plaintext
UPSTREAM_HOST, UPSTREAM_PORT = "127.0.0.1", 9001   # where we send ciphertext
KEY_FILE = "fernet.key"
READ_CHUNK = 4096                                   # max bytes read per await
UPSTREAM_RETRIES = 5                                # attempts to reach the server per device connection


# ─────────────────────────────────────────────────────────────────────────────
# KEY MANAGEMENT (prototype only)
# ─────────────────────────────────────────────────────────────────────────────
def load_or_create_key(path: str = KEY_FILE) -> bytes:
    """
    Load the shared Fernet key from disk, or create it if it doesn't exist.

    os.O_CREAT | os.O_EXCL means "create the file ONLY if it does not already
    exist" as a single atomic operation. So if the gateway and the server both
    start at the same instant, exactly one of them wins and creates the key;
    the other simply reads it. They can never end up with two different keys.

    PROTOTYPE LIMITATION: a key sitting in a file on disk is NOT production key
    management. A real deployment needs per-device keys, a TPM/HSM or secure
    enclave to hold them, and a way to rotate and revoke them.
    """
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)  # 0o600 = owner read/write only
        key = Fernet.generate_key()  # 32 random bytes, base64-encoded (16 for AES, 16 for HMAC)
        with os.fdopen(fd, "wb") as f:
            f.write(key)
        print(f"[GATEWAY] Generated new shared key -> {path}")
        return key
    except FileExistsError:
        with open(path, "rb") as f:
            key = f.read().strip()
        print(f"[GATEWAY] Loaded shared key from {path}")
        return key


# ─────────────────────────────────────────────────────────────────────────────
# UPSTREAM CONNECTION WITH ERROR HANDLING
# ─────────────────────────────────────────────────────────────────────────────
async def connect_upstream():
    """
    Try to reach the secure server, backing off between attempts (1s, 2s, 4s...).

    `await asyncio.sleep(...)` is the key detail: while THIS connection is
    waiting to retry, the event loop keeps serving every OTHER device. A normal
    `time.sleep()` here would freeze the entire gateway.
    """
    delay = 1
    for attempt in range(1, UPSTREAM_RETRIES + 1):
        try:
            return await asyncio.open_connection(UPSTREAM_HOST, UPSTREAM_PORT)
        except OSError as e:
            print(f"[GATEWAY] Secure server unreachable at {UPSTREAM_HOST}:{UPSTREAM_PORT} "
                  f"(attempt {attempt}/{UPSTREAM_RETRIES}: {e}). Retrying in {delay}s...")
            await asyncio.sleep(delay)
            delay = min(delay * 2, 8)
    return None


# ─────────────────────────────────────────────────────────────────────────────
# THE ENCRYPTING PIPE
# ─────────────────────────────────────────────────────────────────────────────
async def encrypt_and_forward(fernet: Fernet, src: asyncio.StreamReader,
                              dst: asyncio.StreamWriter, peer: str) -> None:
    """Read plaintext from the device, encrypt it, push ciphertext upstream. Forever."""
    while True:
        # `await` hands control back to the event loop until bytes arrive.
        # No busy-waiting, no blocked thread.
        chunk = await src.read(READ_CHUNK)
        if not chunk:                      # empty bytes == device closed the connection (EOF)
            print(f"[GATEWAY] {peer} disconnected.")
            return

        token = fernet.encrypt(chunk)      # plaintext bytes -> authenticated ciphertext token
        dst.write(token + b"\n")           # queue it (non-blocking, goes into a buffer)
        await dst.drain()                  # BACKPRESSURE: if the server is slow, pause reading
                                           # from the device instead of buffering unbounded memory.

        # Demo output: show the judges the before/after for the same bytes.
        preview = chunk.decode("utf-8", errors="replace").strip()
        print(f"[GATEWAY] IN  (plaintext, {len(chunk)}B):  {preview[:90]}{'...' if len(preview) > 90 else ''}")
        print(f"[GATEWAY] OUT (ciphertext, {len(token)}B): {token[:60].decode()}...")


async def watch_upstream(reader: asyncio.StreamReader) -> None:
    """
    The server never sends us data, but we still read from it: when read()
    returns b"" the server has closed the connection. This lets us notice a
    dead server immediately instead of on the next failed write.
    """
    while await reader.read(READ_CHUNK):
        pass  # this prototype's server sends nothing back; ignore anything it does
    print("[GATEWAY] Secure server closed the connection.")


async def handle_device(fernet: Fernet, dev_reader: asyncio.StreamReader,
                        dev_writer: asyncio.StreamWriter) -> None:
    """
    Called by asyncio ONCE PER DEVICE CONNECTION, as its own coroutine.
    Ten monitors connecting = ten of these running concurrently on one thread.
    """
    peer = "%s:%s" % dev_writer.get_extra_info("peername")[:2]
    print(f"[GATEWAY] Device connected from {peer}")

    upstream = await connect_upstream()
    if upstream is None:
        # FAIL CLOSED: we would rather drop the connection than ever forward plaintext.
        # The legacy device will reconnect and we'll try again.
        print(f"[GATEWAY] Giving up on secure server for {peer}. Dropping connection (fail-closed).")
        dev_writer.close()
        await dev_writer.wait_closed()
        return
    up_reader, up_writer = upstream
    print(f"[GATEWAY] Tunnel established: {peer} -> [ENCRYPT] -> {UPSTREAM_HOST}:{UPSTREAM_PORT}")

    # Run the encrypting pipe and the upstream watcher side by side.
    # Whichever finishes first (device hangs up OR server dies) tears down both.
    pipe = asyncio.create_task(encrypt_and_forward(fernet, dev_reader, up_writer, peer))
    watcher = asyncio.create_task(watch_upstream(up_reader))
    try:
        done, pending = await asyncio.wait({pipe, watcher}, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        for task in done:
            if task.exception():
                print(f"[GATEWAY] Stream error for {peer}: {task.exception()!r}")
    finally:
        for w in (dev_writer, up_writer):
            w.close()
            try:
                await w.wait_closed()
            except OSError:
                pass
        print(f"[GATEWAY] Tunnel for {peer} closed.")


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
async def main() -> None:
    fernet = Fernet(load_or_create_key())

    try:
        # start_server() registers a listening socket with the event loop.
        # Every new connection spawns handle_device(...) automatically.
        server = await asyncio.start_server(
            lambda r, w: handle_device(fernet, r, w), LISTEN_HOST, LISTEN_PORT
        )
    except OSError as e:
        print(f"[GATEWAY] Cannot listen on {LISTEN_HOST}:{LISTEN_PORT}: {e}")
        print("[GATEWAY] Is another gateway already running?")
        sys.exit(1)

    print(f"[GATEWAY] Listening for legacy plaintext on {LISTEN_HOST}:{LISTEN_PORT}")
    print(f"[GATEWAY] Forwarding ciphertext to {UPSTREAM_HOST}:{UPSTREAM_PORT}")

    # Clean shutdown on Ctrl+C (signal handlers aren't available on Windows' loop).
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except (NotImplementedError, RuntimeError):
            pass

    async with server:
        await stop.wait()
    print("\n[GATEWAY] Shutting down.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[GATEWAY] Shutting down.")