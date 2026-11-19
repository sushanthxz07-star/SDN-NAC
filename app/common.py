"""
common.py - shared helpers for the SDN Authentication & Network Access Control project.

Contains:
  * network addresses / ports used by every component
  * newline-delimited JSON framing over TCP sockets (send_msg / LineReader)
  * SCRAM-style challenge-response crypto (password never sent on the wire)
  * a small event logger that writes human-readable log lines
"""

import hashlib
import hmac
import json
import os
import socket
import threading
import time

# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_DIR = os.path.join(ROOT_DIR, "config")
LOG_DIR = os.path.join(ROOT_DIR, "logs")
RESULTS_DIR = os.path.join(ROOT_DIR, "results")
TOKEN_DIR = "/tmp/nac_tokens"          # per-host session files (Mininet hosts share the FS)

# --------------------------------------------------------------------------
# Addressing plan (must match topology/lab.py and config/policy.json)
# --------------------------------------------------------------------------
AUTH_IP = "10.0.0.100"
AUTH_PORT = 5000                        # TCP authentication service
CTRL_HOST = "127.0.0.1"                 # POX runs in the root namespace
CTRL_PORT = 6699                        # TCP control channel: auth server <-> SDN controller
CTRL_SHARED_KEY = "nac-ctrl-secret-2026"  # pre-shared key for the control channel

WEB_IP, WEB_PORT = "10.0.0.201", 8080   # protected service 1
DB_IP, DB_PORT = "10.0.0.202", 9090     # protected service 2

MAX_LINE = 8192                         # max bytes in one protocol message

# --------------------------------------------------------------------------
# Framing: one JSON object per line
# --------------------------------------------------------------------------


def send_msg(sock, obj):
    """Serialize obj as JSON and send it terminated by '\\n'."""
    data = (json.dumps(obj, separators=(",", ":")) + "\n").encode()
    sock.sendall(data)


class ProtocolError(Exception):
    pass


class LineReader:
    """Buffered reader that returns one decoded JSON message per call.

    TCP is a byte stream, so one recv() can contain half a message or several
    messages. This class keeps a buffer and splits on '\\n'.
    """

    def __init__(self, sock):
        self.sock = sock
        self.buf = b""

    def read_msg(self):
        while b"\n" not in self.buf:
            if len(self.buf) > MAX_LINE:
                raise ProtocolError("message too long")
            chunk = self.sock.recv(4096)
            if not chunk:
                return None                      # peer closed the connection
            self.buf += chunk
        line, self.buf = self.buf.split(b"\n", 1)
        if len(line) > MAX_LINE:
            raise ProtocolError("message too long")
        try:
            obj = json.loads(line.decode())
        except (ValueError, UnicodeDecodeError):
            raise ProtocolError("malformed JSON")
        if not isinstance(obj, dict):
            raise ProtocolError("message must be a JSON object")
        return obj


def request(host, port, obj, timeout=5.0):
    """Open a TCP connection, send one message, return one reply."""
    with socket.create_connection((host, port), timeout=timeout) as s:
        send_msg(s, obj)
        return LineReader(s).read_msg()

# --------------------------------------------------------------------------
# SCRAM-SHA-256 style challenge/response
#
#   SaltedPassword = PBKDF2(password, salt, iterations)
#   ClientKey      = HMAC(SaltedPassword, "Client Key")
#   StoredKey      = SHA256(ClientKey)          <- stored on server
#   ServerKey      = HMAC(SaltedPassword, "Server Key")  <- stored on server
#   AuthMessage    = user:client_nonce:server_nonce
#   ClientProof    = ClientKey XOR HMAC(StoredKey, AuthMessage)   (sent by client)
#   ServerSig      = HMAC(ServerKey, AuthMessage)                 (sent by server)
#
# The password never crosses the network, every login uses fresh nonces
# (replay-proof), and a stolen users.json does not let an attacker log in.
# --------------------------------------------------------------------------
PBKDF2_ITERS = 20000


def _hmac(key, msg):
    return hmac.new(key, msg, hashlib.sha256).digest()


def salted_password(password, salt_hex, iters=PBKDF2_ITERS):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), iters)


def make_credentials(password, iters=PBKDF2_ITERS):
    salt = os.urandom(16).hex()
    sp = salted_password(password, salt, iters)
    client_key = _hmac(sp, b"Client Key")
    return {
        "salt": salt,
        "iters": iters,
        "stored_key": hashlib.sha256(client_key).hexdigest(),
        "server_key": _hmac(sp, b"Server Key").hex(),
    }


def auth_message(user, cnonce, snonce):
    return f"{user}:{cnonce}:{snonce}".encode()


def client_proof(password, salt_hex, iters, user, cnonce, snonce):
    sp = salted_password(password, salt_hex, iters)
    client_key = _hmac(sp, b"Client Key")
    stored_key = hashlib.sha256(client_key).digest()
    sig = _hmac(stored_key, auth_message(user, cnonce, snonce))
    proof = bytes(a ^ b for a, b in zip(client_key, sig)).hex()
    expected_server_sig = _hmac(_hmac(sp, b"Server Key"), auth_message(user, cnonce, snonce)).hex()
    return proof, expected_server_sig


def verify_proof(creds, user, cnonce, snonce, proof_hex):
    """Return the server signature if the proof is valid, else None."""
    try:
        proof = bytes.fromhex(proof_hex)
    except (ValueError, TypeError):
        return None
    stored_key = bytes.fromhex(creds["stored_key"])
    if len(proof) != len(stored_key):
        return None
    sig = _hmac(stored_key, auth_message(user, cnonce, snonce))
    client_key = bytes(a ^ b for a, b in zip(proof, sig))
    if not hmac.compare_digest(hashlib.sha256(client_key).digest(), stored_key):
        return None
    return _hmac(bytes.fromhex(creds["server_key"]), auth_message(user, cnonce, snonce)).hex()

# --------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------


class EventLog:
    """Thread-safe append-only log: '2026-11-18 21:44:01.123 | EVENT | k=v ...'"""

    def __init__(self, name, echo=True):
        os.makedirs(LOG_DIR, exist_ok=True)
        self.path = os.path.join(LOG_DIR, name)
        # the controller runs as a normal user, Mininet hosts as root: keep logs
        # writable by both
        for p, mode in ((LOG_DIR, 0o777), (self.path, 0o666)):
            try:
                if not os.path.exists(p):
                    open(p, "a").close()
                os.chmod(p, mode)
            except OSError:
                pass
        self.lock = threading.Lock()
        self.echo = echo

    def log(self, event, **fields):
        ts = time.strftime("%Y-%m-%d %H:%M:%S") + ".%03d" % (int(time.time() * 1000) % 1000)
        details = " ".join(f"{k}={v}" for k, v in fields.items())
        line = f"{ts} | {event:<14} | {details}"
        with self.lock:
            with open(self.path, "a") as f:
                f.write(line + "\n")
        if self.echo:
            print(line, flush=True)


def load_json(name):
    with open(os.path.join(CONFIG_DIR, name)) as f:
        return json.load(f)
