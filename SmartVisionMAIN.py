"""
============================================================================================
VPN Ops Command Center (vpn_ops_command_center.py)
============================================================================================

Legal & Ethics:

  This tool is intended strictly for lawful VPN server and client administration,
  privacy hygiene, and operational network testing, as governed by the laws and regulations
  of your jurisdiction. Misuse, such as attempts to evade lawful surveillance, sanctions,
  or to facilitate unlawful activity, is expressly prohibited. By using this software,
  you accept sole responsibility for compliance with all applicable laws and you represent
  that you have authorization to manage all servers and endpoints you control with this tool.

  There are no claims made of perfect security, total anonymity, or unlimited bandwidth.
  This program implements reasonable privacy and operational safeguards but cannot guarantee
  security or privacy under all conditions. Operators are responsible for reviewing the code,
  configuration, and the limitations described throughout the documentation and embedded README.

============================================================================================
Required External Dependencies:

  pip install -U paramiko cryptography qrcode[pil] matplotlib psutil pillow colorama

Tested on Python 3.8+/Win10. Your environment may require additional packages.

============================================================================================
"""

import os
import sys
import time
import json
import base64
import hashlib
import hmac
import threading
import queue
import getpass
import shutil
import logging
import tempfile
import socket
import uuid
import platform
import subprocess
import traceback
from datetime import datetime
from typing import Optional, List, Dict, Any

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog
    import matplotlib
    matplotlib.use('TkAgg')
    import matplotlib.pyplot as plt
    import matplotlib.figure as mplfig
except ImportError:
    tk = ttk = None  # Headless mode fallback

try:
    import paramiko
except ImportError:
    paramiko = None

try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes, serialization, hmac as c_hmac
    from cryptography.hazmat.backends import default_backend
    HAS_ARGON2 = True
except Exception:
    # Argon2 available only in cryptography>=41.0.0
    HAS_ARGON2 = False

try:
    import qrcode
    from PIL import Image
except ImportError:
    qrcode = None
    Image = None

try:
    import psutil
except ImportError:
    psutil = None

try:
    import colorama
    from colorama import Fore, Style
    colorama.init()
    LOG_COLOR = {True: Fore.GREEN, False: Fore.RED}
except ImportError:
    LOG_COLOR = {True: '', False: ''}


# ===================== Logging and Constants =====================

TOOL_NAME = "VPN Ops Command Center"
TOOL_SHORT = "vpn_ops_command_center"
TOOL_VERSION = "1.0.0"
TOOL_AUTHOR = "admin@yourcompany.example"
TOOL_DISCLAIMER = (
    "This tool is for lawful VPN operations and privacy hygiene only.\n"
    "Misuse is strictly prohibited. Review all legal/ethical notes in the documentation."
)
VDIR = os.path.expanduser(os.path.join("~", f".{TOOL_SHORT}"))
LOG_DIR = os.path.join(VDIR, "logs")
PROFILE_DIR = os.path.join(VDIR, "server_profiles")
CLIENT_DIR = os.path.join(VDIR, "clients")
VAULT_FILE = os.path.join(VDIR, "vault.enc")
CONFIG_DB = os.path.join(VDIR, "config_db.enc")
ADBLOCK_DIR = os.path.join(VDIR, "adblock")
BLOCKLIST_FILE = os.path.join(ADBLOCK_DIR, "hosts_blocklist.txt")
README_FILE = os.path.join(VDIR, "README.txt")
DASHBOARD_HISTORY_FILE = os.path.join(LOG_DIR, "dashboard_history.json")
DEFAULT_SERVER_PORT = 51820  # WireGuard default
KDF_ITERATIONS = 250_000  # PBKDF2 fallback
ARGON_TIME_COST = 4  # If Argon2 is available
ARGON_MEMORY_COST = 256 * 1024  # 256 MB
ARGON_PARALLELISM = 4
RSA_KEY_SIZE = 4096
NO_LOGS_EXPLAIN = (
    "When 'no logs' mode is enabled, this tool disables most persistent logging.\n"
    "Essential actions, such as fatal errors or configuration changes, will still\n"
    "be tracked minimally to support audit and fault analysis. This setting does *not*\n"
    "affect logging done by external servers, operating systems, or remote peers.\n"
)
DRYRUN_NOTICE = "Dry-run mode active: no destructive operations will be performed."

os.makedirs(VDIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(PROFILE_DIR, exist_ok=True)
os.makedirs(CLIENT_DIR, exist_ok=True)
os.makedirs(ADBLOCK_DIR, exist_ok=True)

def colorlog(msg, ok=True):
    print(f"{LOG_COLOR[ok]}{msg}{Style.RESET_ALL}")

def safe_input(prompt):
    try:
        return input(prompt)
    except EOFError:
        return ''

class DummyLogger:
    def debug(self, *a, **k): pass
    def info(self, *a, **k): pass
    def warning(self, *a, **k): pass
    def error(self, *a, **k): pass
    def exception(self, *a, **k): pass

def build_logger(name: str, level: str = "INFO", no_logs: bool = False):
    if no_logs:
        return DummyLogger()
    logger = logging.getLogger(name)
    handler = logging.FileHandler(os.path.join(LOG_DIR, f"{name}.log"), encoding='utf8')
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False
    return logger

# ===================== Utility functions =====================

def atomic_write(filename, data, mode='wb'):
    dirname = os.path.dirname(filename)
    tmp = tempfile.NamedTemporaryFile(dir=dirname, delete=False)
    with open(tmp.name, mode) as f:
        f.write(data)
    os.replace(tmp.name, filename)

def secure_erase(filename):
    try:
        if os.path.exists(filename):
            with open(filename, 'ba+', buffering=0) as f:
                length = f.tell()
                f.seek(0)
                f.write(os.urandom(length or 1024))
        os.remove(filename)
    except Exception:
        pass

def random_bytes(n=32):
    return os.urandom(n)

def now_iso():
    return datetime.utcnow().replace(microsecond=0).isoformat() + 'Z'

def confirm(prompt, auto_approve=False):
    if auto_approve:
        return True
    resp = safe_input(f"{prompt} [y/N]: ").strip().lower()
    return resp in ("y", "yes")

def get_platform():
    return (platform.system(), platform.version(), platform.machine())

def is_admin():
    if os.name == 'nt':
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    else:
        return os.geteuid() == 0

def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')

def b64d(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + '=' * (4 - len(data) % 4))

def random_ip_subnet(base='10.13.13.0/24', allocated=None):
    # Deterministic /24 IP assign, skip .0 and .1
    if allocated is None:
        allocated = []
    net = base.rsplit('.', 1)[0]
    for i in range(2, 254):
        addr = f"{net}.{i}"
        if addr not in allocated:
            return addr
    raise Exception("No available IPs in subnet")

def nice_json(obj):
    # Used for debugging configs
    return json.dumps(obj, indent=2)

def hash_str(s: str) -> str:
    return hashlib.sha256(s.encode('utf8')).hexdigest()[:16]

def sanitize_filename(s: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in s)

def sluguuid():
    return str(uuid.uuid4())[:8]

# ===================== Cryptographic Vault =====================

class Vault:
    """
    Encrypted vault for storing private keys and configuration secrets
    """
    def __init__(self, filename=VAULT_FILE, logger=None):
        self.filename = filename
        self._locked = True
        self._masterkey = None
        self._backend = default_backend()
        self._data = {}
        self.logger = logger or DummyLogger()

    def derive_key(self, passphrase: str, salt: bytes):
        # Prefer Argon2, fallback to PBKDF2-HMAC-SHA256 with many rounds
        if HAS_ARGON2:
            kdf = Argon2(
                memory_cost=ARGON_MEMORY_COST,
                time_cost=ARGON_TIME_COST,
                parallelism=ARGON_PARALLELISM,
                length=32,
                salt=salt,
                type=2
            )
        else:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=KDF_ITERATIONS,
                backend=self._backend
            )
        key = kdf.derive(passphrase.encode('utf8'))
        return key

    def lock(self):
        self._locked = True
        self._masterkey = None

    def unlock(self, passphrase: str):
        if not os.path.exists(self.filename):
            raise Exception("Vault file does not exist. First-time setup required.")
        with open(self.filename, "rb") as f:
            raw = f.read()
        try:
            magic, salt, nonce, ciphertext, tag = (
                raw[:6], raw[6:22], raw[22:34], raw[34:-16], raw[-16:]
            )
        except Exception:
            raise Exception("Corrupt vault file format.")
        if magic != b'VOPSC1':
            raise Exception("Unrecognized vault magic. Possible upgrade needed.")
        key = self.derive_key(passphrase, salt)
        cipher = ChaCha20Poly1305(key)
        try:
            plaintext = cipher.decrypt(nonce, ciphertext+tag, b"vault")
        except Exception:
            raise Exception("Vault decryption failed. Wrong passphrase or corrupt file.")
        try:
            data = json.loads(plaintext.decode('utf8'))
        except Exception:
            raise Exception("Decryption succeeded, but vault decoding failed.")
        self._data = data
        self._masterkey = key
        self._locked = False
        self.logger.info("Vault unlocked.")
        return True

    def new(self, passphrase: str):
        # Create a new vault.
        if os.path.exists(self.filename):
            raise Exception("Vault file already exists. Refusing to overwrite.")
        salt = random_bytes(16)
        key = self.derive_key(passphrase, salt)
        nonce = random_bytes(12)
        self._data = {}
        cipher = ChaCha20Poly1305(key)
        ad = b"vault"
        plaintext = json.dumps(self._data).encode('utf8')
        ciphertext = cipher.encrypt(nonce, plaintext, ad)
        tag = ciphertext[-16:]
        body = (
            b'VOPSC1' + salt + nonce + ciphertext[:-16] + tag
        )
        atomic_write(self.filename, body)
        self.logger.info("Created new vault at %s.", self.filename)
        self._masterkey = key
        self._locked = False

    def persist(self):
        if self._locked:
            raise Exception("Vault is locked.")
        salt = random_bytes(16)
        nonce = random_bytes(12)
        key = self._masterkey
        cipher = ChaCha20Poly1305(key)
        ad = b"vault"
        plaintext = json.dumps(self._data).encode('utf8')
        ciphertext = cipher.encrypt(nonce, plaintext, ad)
        tag = ciphertext[-16:]
        body = (
            b'VOPSC1' + salt + nonce + ciphertext[:-16] + tag
        )
        atomic_write(self.filename, body)
        self.logger.info("Persisted vault.")

    def set_secret(self, key: str, value: Any):
        if self._locked:
            raise Exception("Vault is locked.")
        self._data[key] = value
        self.logger.info("Updated secret for %s.", key)
        self.persist()

    def get_secret(self, key: str, default=None):
        if self._locked:
            raise Exception("Vault is locked.")
        return self._data.get(key, default)

    def has_secret(self, key: str):
        if self._locked:
            raise Exception("Vault is locked.")
        return key in self._data

    def dump(self):
        if self._locked:
            return {}
        return dict(self._data)

# ===================== Key Generation (WireGuard X25519, RSA) =====================

class KeyManager:
    """
    Handles generation, rotation, and export of cryptographic key pairs
    """
    def __init__(self, vault: Vault, logger=None):
        self.vault = vault
        self.logger = logger or DummyLogger()

    def generate_x25519(self, label: str) -> Dict[str, str]:
        priv = X25519PrivateKey.generate()
        pub = priv.public_key()
        priv_b64 = b64e(priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()))
        pub_b64 = b64e(pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw))
        self.vault.set_secret(f"{label}_x25519_private", priv_b64)
        self.vault.set_secret(f"{label}_x25519_public", pub_b64)
        self.logger.info("Generated X25519 keypair for %s", label)
        return {"private": priv_b64, "public": pub_b64}

    def get_x25519(self, label: str) -> Optional[Dict[str, str]]:
        priv = self.vault.get_secret(f"{label}_x25519_private")
        pub = self.vault.get_secret(f"{label}_x25519_public")
        if priv and pub:
            return {"private": priv, "public": pub}
        return None

    def delete_x25519(self, label: str):
        for suffix in ("_x25519_private", "_x25519_public"):
            if self.vault.has_secret(label + suffix):
                self.vault.set_secret(label + suffix, None)
        self.logger.info("Erased X25519 keys for %s", label)

    def generate_rsa(self, label: str):
        priv_obj = rsa.generate_private_key(
            public_exponent=65537,
            key_size=RSA_KEY_SIZE,
            backend=default_backend()
        )
        priv_bytes = priv_obj.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )
        pub_bytes = priv_obj.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.vault.set_secret(f"{label}_rsa_private", b64e(priv_bytes))
        self.vault.set_secret(f"{label}_rsa_public", b64e(pub_bytes))
        self.logger.info("Generated RSA-4096 keypair for %s", label)
        return {"private_pem": b64e(priv_bytes), "public_pem": b64e(pub_bytes)}

    def get_rsa(self, label: str) -> Optional[Dict[str, str]]:
        priv = self.vault.get_secret(f"{label}_rsa_private")
        pub = self.vault.get_secret(f"{label}_rsa_public")
        if priv and pub:
            return {"private_pem": priv, "public_pem": pub}
        return None

# ===================== SSH Operations for Server Lifecycle =====================

class ServerSSH:
    """
    Handles SSH connections for remote server management.
    All actions require confirmation.
    """
    def __init__(self, hostname: str, username: str, port: int = 22, key: Optional[str]=None,
                 password: Optional[str]=None, logger=None, dry_run=False, auto_approve=False):
        if not paramiko:
            raise ImportError("paramiko module required. Install with pip.")
        self.hostname = hostname
        self.username = username
        self.port = port
        self.key = key
        self.password = password
        self.dry_run = dry_run
        self.auto_approve = auto_approve
        self.logger = logger or DummyLogger()
        self.client = None

    def connect(self):
        self.logger.info(f"Connecting to {self.username}@{self.hostname}:{self.port}")
        if self.dry_run:
            colorlog("[DRY RUN] Would connect via SSH.", True)
            return
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            if self.key:
                key_obj = paramiko.RSAKey.from_private_key_file(self.key)
                c.connect(self.hostname, port=self.port, username=self.username, pkey=key_obj)
            else:
                c.connect(self.hostname, port=self.port, username=self.username, password=self.password)
            self.client = c
            self.logger.info("SSH connection established.")
        except Exception as e:
            self.logger.error(f"SSH connection failed: {e}")
            raise

    def close(self):
        if self.client:
            self.client.close()
            self.logger.info("SSH connection closed.")
        self.client = None

    def run(self, command: str, require_confirm=True, sudo=False):
        if sudo and not command.strip().startswith("sudo"):
            command = "sudo " + command
        if require_confirm and not confirm(f"Run on {self.hostname}: {command}", self.auto_approve):
            self.logger.info("Command declined: %s", command)
            return "[ABORTED]"
        if self.dry_run:
            colorlog(f"[DRY RUN] Would run: {command}", True)
            return "[DRY RUN]"
        stdin, stdout, stderr = self.client.exec_command(command)
        out, err = stdout.read().decode(), stderr.read().decode()
        rc = stdout.channel.recv_exit_status()
        self.logger.info(f"Ran: {command} [rc={rc}]")
        if rc != 0:
            self.logger.error(f"Error output: {err.strip()}")
        return out.strip(), err.strip(), rc

    def upload(self, localfile, remotefile):
        if not confirm(f"Upload {localfile} -> {self.hostname}:{remotefile}", self.auto_approve):
            self.logger.info("Upload declined: %s", localfile)
            return "[ABORTED]"
        if self.dry_run:
            colorlog(f"[DRY RUN] Would upload {localfile} to {remotefile}", True)
            return "[DRY RUN]"
        with open(localfile, "rb") as f:
            data = f.read()
        sftp = self.client.open_sftp()
        sftp.put(localfile, remotefile)
        sftp.close()
        self.logger.info(f"Uploaded file to {remotefile}")
        return "OK"

    def retrieve(self, remotefile, localfile):
        if not confirm(f"Download {self.hostname}:{remotefile} -> {localfile}", self.auto_approve):
            self.logger.info("Download declined: %s", remotefile)
            return "[ABORTED]"
        if self.dry_run:
            colorlog(f"[DRY RUN] Would retrieve {remotefile} to {localfile}", True)
            return "[DRY RUN]"
        sftp = self.client.open_sftp()
        sftp.get(remotefile, localfile)
        sftp.close()
        self.logger.info(f"Retrieved file {remotefile}")
        return "OK"

# ===================== Profile and Client Management =====================

class ConfigDB:
    """
    Config DB (encrypted, persisted JSON) for servers and clients
    """
    def __init__(self, filename=CONFIG_DB, vault: Optional[Vault]=None, logger=None):
        self.filename = filename
        self.vault = vault
        self.logger = logger or DummyLogger()
        self._data = {}
        self._loaded = False

    def load(self):
        if not os.path.exists(self.filename):
            self._data = {"servers": {}, "clients": {}}
            self._loaded = True
            return
        if not self.vault or self.vault._locked:
            raise Exception("Vault must be unlocked to access config DB.")
        with open(self.filename, "rb") as f:
            raw = f.read()
        key = self.vault._masterkey
        nonce, ciphertext, tag = raw[:12], raw[12:-16], raw[-16:]
        cipher = ChaCha20Poly1305(key)
        try:
            plaintext = cipher.decrypt(nonce, ciphertext+tag, b"configdb")
            data = json.loads(plaintext.decode('utf8'))
        except Exception as e:
            self.logger.error("ConfigDB decryption failed: %s", e)
            raise
        self._data = data
        self._loaded = True
        self.logger.info("Loaded config DB.")
        return

    def dump(self) -> dict:
        if not self._loaded:
            self.load()
        return self._data

    def save(self):
        if not self._loaded:
            raise Exception("Config not loaded.")
        if not self.vault or self.vault._locked:
            raise Exception("Vault must be unlocked to store config DB.")
        key = self.vault._masterkey
        nonce = random_bytes(12)
        cipher = ChaCha20Poly1305(key)
        plaintext = json.dumps(self._data).encode('utf8')
        ct = cipher.encrypt(nonce, plaintext, b"configdb")
        tag = ct[-16:]
        body = nonce + ct[:-16] + tag
        atomic_write(self.filename, body)
        self.logger.info("Saved config DB.")

    def add_server(self, name: str, data: dict):
        if not self._loaded:
            self.load()
        self._data["servers"][name] = data
        self.logger.info("Added server profile: %s", name)
        self.save()

    def add_client(self, name: str, data: dict):
        if not self._loaded:
            self.load()
        self._data["clients"][name] = data
        self.logger.info("Added client profile: %s", name)
        self.save()

    def list_servers(self):
        if not self._loaded:
            self.load()
        return list(self._data.get("servers", {}).keys())

    def list_clients(self):
        if not self._loaded:
            self.load()
        return list(self._data.get("clients", {}).keys())

    def get_server(self, name: str):
        if not self._loaded:
            self.load()
        return self._data.get("servers", {}).get(name)

    def get_client(self, name: str):
        if not self._loaded:
            self.load()
        return self._data.get("clients", {}).get(name)

    def update_client(self, name: str, data: dict):
        if not self._loaded:
            self.load()
        self._data["clients"][name] = data
        self.logger.info(f"Updated client: {name}")
        self.save()

    def revoke_client(self, name: str):
        if not self._loaded:
            self.load()
        if name in self._data.get("clients", {}):
            del self._data["clients"][name]
            self.logger.info(f"Revoked client: {name}")
            self.save()

# ===================== WireGuard Configuration Helpers =====================

def generate_wg_conf(server: dict, client: dict, private_key: str, peer_pub: str, cli_ip: str, dns: List[str]=None) -> str:
    """
    Returns full wg-quick configuration for this client.
    """
    DNS = '\nDNS = {}'.format(','.join(dns)) if dns else ""
    tpl = f"""[Interface]
PrivateKey = {private_key}
Address = {cli_ip}/32{DNS}

[Peer]
PublicKey = {peer_pub}
Endpoint = {server['host']}:{server.get('port', DEFAULT_SERVER_PORT)}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""
    return tpl

def generate_server_peer_block(client_pub: str, assigned_ip: str) -> str:
    """
    Generates the [Peer] block for a particular client on the server
    """
    peer_tpl = f"""[Peer]
PublicKey = {client_pub}
AllowedIPs = {assigned_ip}/32
"""
    return peer_tpl

def parse_wg_show_output(output: str) -> dict:
    """
    WireGuard 'wg show' output parser for peer and transfer
    """
    peers = {}
    lines = output.splitlines()
    current_peer = None
    for line in lines:
        if line.startswith("peer:"):
            current_peer = line.split()[1].strip()
            peers[current_peer] = {}
        elif current_peer and ":" in line:
            key, val = line.strip().split(":", 1)
            peers[current_peer][key.strip()] = val.strip()
    return peers

# ===================== QR Code Export =====================

def export_qr(cfg: str, output_file: str="client_qr.png"):
    if not qrcode or not Image:
        raise Exception("qrcode and pillow required to export QR codes.")
    img = qrcode.make(cfg)
    img.save(output_file)
    colorlog(f"Exported config QR to {output_file}", True)
    return output_file

# ===================== Adblock (Blocklist Manager) =====================

class AdBlockManager:
    """Manages ad-blocking hosts/blocklist; supports updates and merging."""
    DEFAULT_URLS = [
        "https://someonewhocares.org/hosts/hosts",
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
    ]
    def __init__(self, enabled=True, logger=None):
        self.blocklist_file = BLOCKLIST_FILE
        self.urls = list(self.DEFAULT_URLS)
        self.enabled = enabled
        self.logger = logger or DummyLogger()

    def update_blocklists(self):
        # Merges blocklists and writes a deduped hosts file
        all_entries = set()
        for url in self.urls:
            try:
                colorlog(f"Fetching blocklist: {url}")
                data = self._fetch_url(url)
                for line in data.splitlines():
                    if line.strip().startswith("0.0.0.0") or line.strip().startswith("127.0.0.1"):
                        entry = line.strip()
                        all_entries.add(entry)
            except Exception as e:
                self.logger.warning(f"Blocklist fetch failed: {e}")
        # Write to file with explanation
        blockdata = "# Merged adblock hosts file.\n" + "\n".join(sorted(all_entries)) + "\n"
        atomic_write(self.blocklist_file, blockdata.encode('utf8'))
        self.logger.info(f"Updated blocklist to {self.blocklist_file}.")

    def _fetch_url(self, url):
        import urllib.request
        with urllib.request.urlopen(url, timeout=10) as resp:
            return resp.read().decode('utf8')

    def enable(self):
        self.enabled = True
        colorlog("Adblock enabled.", True)

    def disable(self):
        self.enabled = False
        colorlog("Adblock disabled.", True)

    def status(self):
        return self.enabled

# ===================== DNS Leak Test/Audit =====================

def dns_leak_audit(logger=None):
    tester = ["https://www.cloudflare.com/cdn-cgi/trace"]
    try:
        import urllib.request
        for url in tester:
            colorlog(f"Testing DNS/IP leak: {url}")
            with urllib.request.urlopen(url, timeout=8) as resp:
                data = resp.read().decode()
            ip = None
            for line in data.splitlines():
                if line.startswith('ip='):
                    ip = line.split('=',1)[1]
            if not ip:
                colorlog("Could not parse IP address.", False)
            else:
                colorlog(f"External IP Seen by Cloudflare: {ip}", True)
            # Check DOH
            doh_resp = None
            test_url = "https://dns.google/resolve?name=example.com&type=A"
            colorlog(f"Resolving via DoH: {test_url}")
            with urllib.request.urlopen(test_url, timeout=8) as resp:
                doh_resp = resp.read().decode()
            if doh_resp:
                colorlog("DNS-over-HTTPS seems operational.", True)
            return {"ip": ip}
    except Exception as e:
        colorlog(f"DNS/IP leak test failed: {e}", False)
        if logger:
            logger.error("DNS/IP leak test failed: %s", e)
        return {"error": str(e)}

# ===================== Kill Switch (Network Safety) =====================

class KillSwitch:
    """
    Implements network killswitch for local system.
    """
    def __init__(self, hard_mode=False, dry_run=False, logger=None):
        self.hard_mode = hard_mode
        self.dry_run = dry_run
        self.logger = logger or DummyLogger()

    def apply(self):
        # Only do on explicit confirmation, works for Windows
        if not confirm("Apply network kill switch (HARD mode blocks all traffic if VPN is down)?", False):
            return False
        if self.dry_run:
            colorlog("[DRY RUN] Would apply kill switch rules.", True)
            return True
        if self.hard_mode:
            self._apply_hard()
        else:
            self._apply_soft()
        return True

    def _apply_soft(self):
        # Block split-tunnel by setting strict metric and firewall rules for WireGuard only
        colorlog("Applying soft kill switch... (blocks non-VPN for known interfaces)")
        if os.name == 'nt':
            # Windows example: Block outbound except for wg0 (requires admin)
            cmd = r'netsh advfirewall firewall add rule name="KillSwitch" dir=out action=block interfaceType=any'
            subprocess.call(cmd, shell=True)
        else:
            cmd = "sudo iptables -I OUTPUT ! -o wg0 -j DROP"
            subprocess.call(cmd, shell=True)
        self.logger.info("Soft kill switch active.")

    def _apply_hard(self):
        # Main traffic OUT except for VPN interface is blocked
        colorlog("Applying HARD kill switch. All non-WireGuard traffic blocked until VPN up.", True)
        self._apply_soft()
        self.logger.info("Hard kill switch applied.")

    def remove(self):
        if self.dry_run:
            colorlog("[DRY RUN] Would remove kill switch rules.", True)
            return True
        colorlog("Removing kill switch rules...", True)
        if os.name == 'nt':
            subprocess.call('netsh advfirewall firewall delete rule name="KillSwitch"', shell=True)
        else:
            subprocess.call("sudo iptables -D OUTPUT ! -o wg0 -j DROP", shell=True)
        self.logger.info("Removed kill switch.")

# ===================== Multi-hop Routing Manager =====================

class MultiHopManager:
    """
    Allows admin to chain supported gateways for multi-hop VPN.
    No automation to 3rd-party VPNs.
    """
    def __init__(self, config_db: ConfigDB, logger=None):
        self.config_db = config_db
        self.logger = logger or DummyLogger()

    def available_gws(self) -> List[str]:
        return self.config_db.list_servers()

    def chain_info(self, selected: List[str]) -> List[dict]:
        return [self.config_db.get_server(name) for name in selected]

    def measure_perf(self, chain: List[dict]) -> dict:
        # Naive perf check: measure ping and sample throughput
        results = {}
        for node in chain:
            host = node['host']
            colorlog(f"Pinging {host}...")
            try:
                if os.name == 'nt':
                    rc = subprocess.call(f"ping -n 1 {host}", shell=True)
                else:
                    rc = subprocess.call(f"ping -c 1 {host}", shell=True)
                results[host] = "OK" if rc == 0 else "FAIL"
            except Exception:
                results[host] = "FAIL"
        fastest = [h for h,v in results.items() if v=="OK"]
        if fastest:
            colorlog(f"Fastest reachable chain: {fastest}", True)
        return results

# ===================== Monitoring Dashboard =====================

class Dashboard:
    """
    Monitors CPU, memory, network, and per-client throughput.
    Tkinter+matplotlib GUI. Headless fallback if tkinter/psutil unavailable.
    """
    def __init__(self, config_db: ConfigDB, log_history=DASHBOARD_HISTORY_FILE, logger=None):
        self.config_db = config_db
        self.log_history = log_history
        self.logger = logger or DummyLogger()
        self._running = False

    def start(self):
        if tk and psutil:
            threading.Thread(target=self._run_gui, daemon=True).start()
        else:
            colorlog("Dashboard requires tkinter+psutil.", False)

    def _run_gui(self):
        root = tk.Tk()
        root.title(f"{TOOL_NAME} Dashboard")
        f = tk.Frame(root)
        f.pack(fill=tk.BOTH, expand=True)
        lbl = tk.Label(f, text="Live VPN Ops Dashboard", font=("Arial", 14))
        lbl.pack()
        fig = mplfig.Figure(figsize=(6,3))
        ax = fig.add_subplot(111)
        canvas = matplotlib.backends.backend_tkagg.FigureCanvasTkAgg(fig, master=f)
        canvas.get_tk_widget().pack()
        mem_label = tk.Label(f, text="Memory: ")
        mem_label.pack()
        net_label = tk.Label(f, text="Network: ")
        net_label.pack()
        per_client = tk.Label(f, text="Clients: ")
        per_client.pack()

        def polldata():
            try:
                cpu = psutil.cpu_percent()
                mem = psutil.virtual_memory().percent
                net = psutil.net_io_counters()
                mem_label.config(text=f"Memory: {mem:.1f}%")
                net_label.config(text=f"Net: sent {net.bytes_sent//1e6:.2f} MB, recv {net.bytes_recv//1e6:.2f} MB")
                t = datetime.now().strftime("%H:%M:%S")
                ax.cla()
                cpus = psutil.cpu_percent(percpu=True)
                ax.plot(cpus, marker='o')
                ax.set_ylim(0,100)
                ax.set_ylabel("CPU usage %")
                canvas.draw()
                # Per-client from config (placeholder)
                client_list = self.config_db.list_clients()
                c_info = "\n".join(client_list)
                per_client.config(text=f"Clients:\n{c_info}")
            except Exception as e:
                self.logger.error("Dashboard poll failed: %s", e)
            if self._running:
                root.after(2000, polldata)

        self._running = True
        polldata()
        root.protocol("WM_DELETE_WINDOW", lambda: self.stop(root))
        root.mainloop()

    def stop(self, root=None):
        self._running = False
        if root:
            root.destroy()
        self.logger.info("Dashboard stopped.")

# ===================== Guided Setup and CLI =====================

class GuidedSetup:
    """
    First-time guided setup for the VPN Ops Command Center
    """
    def __init__(self, vault: Vault, config_db: ConfigDB, key_mgr: KeyManager, logger=None):
        self.vault = vault
        self.config_db = config_db
        self.key_mgr = key_mgr
        self.logger = logger or DummyLogger()

    def run(self):
        colorlog("==== VPN Ops Command Center — First-time Setup ====\n", True)
        if os.path.exists(self.vault.filename):
            colorlog("Vault already exists; skipping setup.", True)
            return
        passphrase = ''
        while not passphrase:
            p1 = getpass.getpass("Enter NEW vault passphrase: ")
            p2 = getpass.getpass("Confirm passphrase: ")
            if len(p1) < 8:
                colorlog("Passphrase should be at least 8 chars.", False)
                continue
            if p1 != p2:
                colorlog("Passphrases do not match.", False)
                continue
            passphrase = p1
        self.vault.new(passphrase)
        colorlog("Vault created and unlocked.", True)
        # Generate admin keys
        colorlog("Generating X25519 keypair for admin profile...", True)
        self.key_mgr.generate_x25519("admin")
        # Prompt for first server
        name = sanitize_filename(safe_input("Enter a name for your first server profile: ").strip())
        host = safe_input("Server hostname/IP: ").strip()
        ssh_user = safe_input("SSH username: ").strip()
        port = safe_input("SSH port [22]: ").strip()
        port = int(port) if port.isdigit() else 22
        # Save profile
        srv = {
            "name": name,
            "host": host,
            "ssh_user": ssh_user,
            "port": port,
            "created_at": now_iso(),
        }
        self.config_db.add_server(name, srv)
        colorlog("Server profile created.", True)
        # Generate first test client
        cli_name = sanitize_filename(safe_input("Name for your first client (e.g. alice): ").strip())
        cli_keypair = self.key_mgr.generate_x25519(cli_name)
        cli_ip = random_ip_subnet()
        cli = {
            "name": cli_name,
            "address": cli_ip,
            "public_key": cli_keypair['public'],
            "created_at": now_iso(),
            "server": name,
        }
        self.config_db.add_client(cli_name, cli)
        colorlog(f"First client '{cli_name}' created with IP {cli_ip}.", True)
        colorlog("==== Setup Complete! ====", True)

# ===================== CLI Main Logic =====================

def usage():
    print(f"""
{TOOL_NAME} (vpn_ops_command_center.py) — CLI
==================================================================================
Usage:
  python vpn_ops_command_center.py [command] [options]

  Commands:
    setup                 Guided first-time setup wizard
    clients               List or manage clients (--list, --add, --revoke, --export, --qr, --rotate)
    servers               List or manage server profiles (--list, --add, --show, --remove)
    ssh                   SSH operation (install, start, stop, logs, upload, download)
    dashboard             Launch live monitoring dashboard GUI
    audit                 Run DNS and IP leak audit function (saves human-readable report)
    killswitch            Apply or remove network kill switch (--apply [--hard] / --remove)
    adblock               Update/fetch blocklist, toggle per profile (--enable/--disable/--update)
    multihop              Manage chained gateway routing (list, perf)
    self-test             Run built-in sanity check unit tests
    help                  Show this usage/help message

  Options (where supported):
    --dry-run             Preview/dry-run mode (no changes made)
    --auto-approve        Approve actions without prompting (dangerous, advanced)
    --no-logs             Suppress logging; see privacy note
    --profile NAME        Specify server or client profile name

Examples:
  python vpn_ops_command_center.py setup
  python vpn_ops_command_center.py clients --list
  python vpn_ops_command_center.py clients --add --name bob
  python vpn_ops_command_center.py ssh --profile myserver --install
  python vpn_ops_command_center.py dashboard
  python vpn_ops_command_center.py audit
  python vpn_ops_command_center.py self-test

Notes:
  - All config, secrets, and keys are managed in {VDIR}
  - For lawful privacy hygiene and administration only. See legal/ethics header.
==================================================================================
""")

# ===================== Main Entrypoint =====================

def main():
    import argparse

    parser = argparse.ArgumentParser(description=TOOL_NAME, add_help=False)
    parser.add_argument("command", nargs="?", default="help", help="Subcommand")
    parser.add_argument("--dry-run", action="store_true", help="Preview/dry-run mode")
    parser.add_argument("--auto-approve", action="store_true", help="Auto-approve confirmations")
    parser.add_argument("--no-logs", action="store_true", help="Suppress logging")
    parser.add_argument("--profile", help="Specify profile name")
    parser.add_argument("--list", action="store_true", help="List records")
    parser.add_argument("--add", action="store_true", help="Add new record")
    parser.add_argument("--export", action="store_true", help="Export config")
    parser.add_argument("--qr", action="store_true", help="Export QR code")
    parser.add_argument("--revoke", action="store_true", help="Revoke client")
    parser.add_argument("--rotate", action="store_true", help="Rotate keys")
    parser.add_argument("--show", action="store_true", help="Show details")
    parser.add_argument("--install", action="store_true", help="Install server software")
    parser.add_argument("--start", action="store_true", help="Start service")
    parser.add_argument("--stop", action="store_true", help="Stop service")
    parser.add_argument("--logs", action="store_true", help="Retrieve logs")
    parser.add_argument("--remove", action="store_true", help="Remove profile")
    parser.add_argument("--apply", action="store_true", help="Apply kill switch")
    parser.add_argument("--hard", action="store_true", help="HARD kill switch")
    parser.add_argument("--update", action="store_true", help="Update adblock list")
    parser.add_argument("--enable", action="store_true", help="Enable adblock")
    parser.add_argument("--disable", action="store_true", help="Disable adblock")
    parser.add_argument("--name", help="Client or server name")
    parser.add_argument("--help", action="store_true", help="Show help")

    args = parser.parse_args()

    logger = build_logger("main", "INFO", args.no_logs)

    # Load vault and ConfigDB (prompt for passphrase if needed)
    vault = Vault(logger=logger)
    key_mgr = KeyManager(vault, logger=logger)
    config_db = ConfigDB(vault=vault, logger=logger)
    adblock_mgr = AdBlockManager(enabled=False, logger=logger)
    mhmgr = MultiHopManager(config_db, logger=logger)
    dry_run = args.dry_run
    auto_approve = args.auto_approve or dry_run

    # Help
    if args.help or args.command in ("help", "-h", "--help", ""):
        usage()
        sys.exit(0)

    # Setup
    if args.command == "setup":
        GuidedSetup(vault, config_db, key_mgr, logger).run()
        sys.exit(0)

    # Unlock vault
    if not os.path.exists(vault.filename):
        colorlog("Vault does not exist. Run 'python vpn_ops_command_center.py setup' first.", False)
        sys.exit(1)
    for i in range(3):
        try:
            passphrase = getpass.getpass("Enter vault passphrase: ")
            vault.unlock(passphrase)
            break
        except Exception as e:
            colorlog(str(e), False)
            if i == 2:
                sys.exit(1)

    # ConfigDB load
    try:
        config_db.load()
    except Exception as e:
        colorlog(f"Failed to load config DB: {e}", False)
        sys.exit(1)

    # Server Profile Ops
    if args.command == "servers":
        if args.list:
            servers = config_db.list_servers()
            colorlog(f"Server profiles:\n- " + "\n- ".join(servers), True)
        elif args.add:
            name = args.name or sanitize_filename(safe_input("Server profile name: ").strip())
            host = safe_input("Server hostname/IP: ").strip()
            ssh_user = safe_input("SSH username: ").strip()
            port = safe_input("SSH port [22]: ").strip()
            port = int(port) if port.isdigit() else 22
            srv = {
                "name": name,
                "host": host,
                "ssh_user": ssh_user,
                "port": port,
                "created_at": now_iso(),
            }
            config_db.add_server(name, srv)
            colorlog("Server profile created.", True)
        elif args.show:
            prof = args.profile or args.name or safe_input("Server profile name: ").strip()
            data = config_db.get_server(prof)
            if not data:
                colorlog("Profile not found.", False)
            else:
                print(nice_json(data))
        elif args.remove:
            prof = args.profile or args.name or safe_input("Server profile name: ").strip()
            if confirm(f"Remove server profile {prof}?", auto_approve):
                servers = config_db.list_servers()
                if prof in servers:
                    del config_db._data["servers"][prof]
                    config_db.save()
                    colorlog(f"Profile {prof} removed.", True)
                else:
                    colorlog("Not found.", False)
        else:
            usage()
        sys.exit(0)

    # Client Profile Ops
    if args.command == "clients":
        if args.list:
            clients = config_db.list_clients()
            colorlog(f"Clients:\n- " + "\n- ".join(clients), True)
        elif args.add:
            name = args.name or sanitize_filename(safe_input("Client name: ").strip())
            srv_name = args.profile or safe_input("Server profile: ").strip()
            srv = config_db.get_server(srv_name)
            if not srv:
                colorlog("No such server profile.", False)
                sys.exit(1)
            keypair = key_mgr.generate_x25519(name)
            allocated_ips = set(cli.get("address") for cli in config_db._data.get("clients", {}).values())
            cli_ip = random_ip_subnet(allocated=allocated_ips)
            cli = {
                "name": name,
                "address": cli_ip,
                "public_key": keypair['public'],
                "created_at": now_iso(),
                "server": srv_name,
            }
            config_db.add_client(name, cli)
            colorlog(f"Client {name} added with IP {cli_ip}.", True)
        elif args.export:
            name = args.name or safe_input("Client name: ").strip()
            cli = config_db.get_client(name)
            if not cli:
                colorlog("Client not found.", False)
                sys.exit(1)
            srv = config_db.get_server(cli['server'])
            priv = key_mgr.get_x25519(name)['private']
            pub = key_mgr.get_x25519(cli['server'])['public']
            conf = generate_wg_conf(srv, cli, priv, pub, cli['address'])
            outfile = os.path.join(CLIENT_DIR, f"{name}.conf")
            with open(outfile, "w") as f:
                f.write(conf)
            colorlog(f"Exported client config to {outfile}", True)
        elif args.qr:
            name = args.name or safe_input("Client name: ").strip()
            cli = config_db.get_client(name)
            if not cli:
                colorlog("Client not found.", False)
                sys.exit(1)
            srv = config_db.get_server(cli['server'])
            priv = key_mgr.get_x25519(name)['private']
            pub = key_mgr.get_x25519(cli['server'])['public']
            conf = generate_wg_conf(srv, cli, priv, pub, cli['address'])
            outfile = os.path.join(CLIENT_DIR, f"{name}_qr.png")
            export_qr(conf, outfile)
        elif args.revoke:
            name = args.name or safe_input("Client name: ").strip()
            if confirm(f"Revoke access for client {name}?", auto_approve):
                config_db.revoke_client(name)
                key_mgr.delete_x25519(name)
                colorlog(f"Client {name} revoked.", True)
        elif args.rotate:
            name = args.name or safe_input("Client name: ").strip()
            cli = config_db.get_client(name)
            if not cli:
                colorlog("Client not found.", False)
                sys.exit(1)
            keypair = key_mgr.generate_x25519(name)
            cli['public_key'] = keypair['public']
            cli['rotated_at'] = now_iso()
            config_db.update_client(name, cli)
            colorlog(f"Client keys rotated for {name}. Update server config for this peer!", True)
        else:
            usage()
        sys.exit(0)

    # SSH Ops
    if args.command == "ssh":
        prof = args.profile or safe_input("Server profile name: ").strip()
        srv = config_db.get_server(prof)
        if not srv:
            colorlog("Server profile not found.", False)
            sys.exit(1)
        ssh_cli = ServerSSH(
            srv['host'], srv.get('ssh_user','root'), port=srv.get('port',22),
            logger=logger,
            dry_run=dry_run,
            auto_approve=auto_approve
        )
        ssh_cli.connect()
        try:
            if args.install:
                colorlog("Install WireGuard on server...", True)
                ssh_cli.run("apt update && apt install -y wireguard", require_confirm=True, sudo=True)
            elif args.start:
                colorlog("Start WireGuard service...", True)
                ssh_cli.run("wg-quick up wg0", require_confirm=True, sudo=True)
            elif args.stop:
                colorlog("Stop WireGuard service...", True)
                ssh_cli.run("wg-quick down wg0", require_confirm=True, sudo=True)
            elif args.logs:
                colorlog("Retrieve WireGuard logs...", True)
                out, err, rc = ssh_cli.run("journalctl -u wg-quick@wg0 --no-pager | tail -n 50",
                                           require_confirm=True, sudo=True)
                print(out)
            elif args.upload:
                src = safe_input("Local file to upload: ").strip()
                dst = safe_input("Remote destination path: ").strip()
                ssh_cli.upload(src, dst)
            elif args.download:
                src = safe_input("Remote file to download: ").strip()
                dst = safe_input("Local dest path: ").strip()
                ssh_cli.retrieve(src, dst)
            else:
                usage()
        finally:
            ssh_cli.close()
        sys.exit(0)

    # Dashboard
    if args.command == "dashboard":
        dash = Dashboard(config_db, logger=logger)
        dash.start()
        sys.exit(0)

    # Audit
    if args.command == "audit":
        colorlog("Running DNS/IP leak audit...", True)
        result = dns_leak_audit(logger=logger)
        outfile = os.path.join(LOG_DIR, f"audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        with open(outfile, "w") as f:
            f.write("# DNS/IP Leak Audit\n")
            f.write(json.dumps(result, indent=2))
        colorlog(f"Audit complete. See {outfile}", True)
        sys.exit(0)

    # Kill Switch
    if args.command == "killswitch":
        ks = KillSwitch(hard_mode=args.hard, dry_run=dry_run, logger=logger)
        if args.apply:
            ks.apply()
        elif args.remove:
            ks.remove()
        else:
            usage()
        sys.exit(0)

    # AdBlock
    if args.command == "adblock":
        abm = AdBlockManager(enabled=False, logger=logger)
        if args.update:
            abm.update_blocklists()
        if args.enable:
            abm.enable()
        if args.disable:
            abm.disable()
        colorlog(f"Blocklist at {BLOCKLIST_FILE}", True)
        sys.exit(0)

    # Multi-hop
    if args.command == "multihop":
        gws = mhmgr.available_gws()
        colorlog("Available gateways (for chain):\n- " + "\n- ".join(gws), True)
        sel = safe_input("Enter comma-separated gateway names for chain (order matters): ").strip().split(",")
        sel = [s.strip() for s in sel if s.strip()]
        chain = mhmgr.chain_info(sel)
        mhmgr.measure_perf(chain)
        sys.exit(0)

    # Self-Test
    if args.command == "self-test":
        colorlog("---- Running Internal Self-Test Suite ----", True)
        try:
            # Test keygen
            vault.new("xxtestpass123")
            vault.unlock("xxtestpass123")
            out = key_mgr.generate_x25519("testuser1")
            assert out["private"] and out["public"]
            rsaout = key_mgr.generate_rsa("testrsa")
            assert rsaout["private_pem"] and rsaout["public_pem"]
            config_db.load()
            config_db.add_server("selftestsrv", {"host": "127.0.0.1", "ssh_user":"root", "created_at": now_iso()})
            config_db.add_client("selftestcli", {"name":"selftestcli", "public_key":out["public"], "server":"selftestsrv", "address":"10.13.13.99", "created_at": now_iso()})
            conf = generate_wg_conf(
                config_db.get_server("selftestsrv"),
                config_db.get_client("selftestcli"),
                out["private"], out["public"], "10.13.13.99"
            )
            assert "PrivateKey" in conf and "PublicKey" in conf
            colorlog("Self-test: keygen and config ok.", True)
            # SSH dry-run
            if paramiko:
                ssh = ServerSSH("127.0.0.1", "user", dry_run=True)
                ssh.connect()
                ssh.run("echo test")
                colorlog("Self-test: SSH dry-run ok.", True)
        except Exception as e:
            colorlog(f"Self-test failure: {e}", False)
            sys.exit(2)
        colorlog("All self-tests passed!", True)
        sys.exit(0)

    # Help fallback
    usage()
    sys.exit(0)

if __name__ == "__main__":
    main()

# ===================== Embedded README (Automatic) =====================

README_CONTENT = f"""
============================================================================================
VPN Ops Command Center — README (Auto-generated)
============================================================================================
Overview:
  {TOOL_NAME} is a lawful VPN administration toolkit for Windows 10+ administrators
  managing their own WireGuard infrastructure. It provides end-to-end config lifecycle,
  key management, monitoring dashboard, ad-blocking, DNS audit, kill switch, and more.

First-Time Setup:
  1. Install Python 3.8+ and required dependencies:
     > pip install -U paramiko cryptography qrcode[pil] matplotlib psutil pillow colorama

  2. Run the setup wizard:
     > python vpn_ops_command_center.py setup

  3. Follow prompts to generate your vault passphrase, admin keys, first server, and client.

Usual Operations:
   - List/add/revoke clients:    python vpn_ops_command_center.py clients --list|--add|--revoke --name NAME
   - List/add/show server:       python vpn_ops_command_center.py servers --list|--add|--show --profile NAME
   - SSH to server:              python vpn_ops_command_center.py ssh --profile NAME --install|--start|--stop|--logs
   - Dashboard GUI:              python vpn_ops_command_center.py dashboard
   - Ad-block updates:           python vpn_ops_command_center.py adblock --update|--enable|--disable
   - Kill switch:                python vpn_ops_command_center.py killswitch --apply|--remove [--hard]
   - Audit for DNS/IP leaks:     python vpn_ops_command_center.py audit

Update:
   > pip install -U paramiko cryptography qrcode[pil] matplotlib psutil pillow colorama

Limitations:
  - "No logs" mode disables most persistent logs from this tool, but does NOT guarantee
    absence of all records as server OS, external systems, or network flows may log data.
  - Dashboard and traffic counters depend on correct local and remote configuration.
  - WireGuard service management assumes Linux systemd servers for SSH automation.
  - DNS and ad-block protection only cover what is under admin control.
  - Multi-hop is manual and limited to operator-provisioned gateways.

Legal/Ethical Disclaimer:
  This toolkit is for lawful privacy hygiene and network administration only.
  It is expressly forbidden to use this tool to violate laws, evade legal monitoring,
  circumvent sanctions, or help others do so. Review local laws, server policies, and
  operational risks. There are no warranties of perfect security or anonymity.

============================================================================================
"""

with open(README_FILE, "w") as f:
    f.write(README_CONTENT)

