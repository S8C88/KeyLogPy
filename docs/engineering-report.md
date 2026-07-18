# KeyLogPy — Engineering Report

## Overview

KeyLogPy is a config-driven keystroke logger built for red-team operations. Emphasizes operational security (encrypted storage, network exfiltration with minimal beaconing) and modular configuration over hardcoded behavior.

## Architecture

### Core Components

1. **KeyListener** — wraps pynput's `Listener`, processes key events into characters
2. **LogManager** — handles buffer rotation, file I/O, and encryption
3. **CryptoEngine** — AES-256-CBC encryption with HMAC-SHA256 authentication
4. **Exfiltrator** — dual-channel (webhook + SMTP) encrypted exfiltration
5. **ConfigManager** — YAML + CLI config merger
6. **StealthManager** — platform-specific process hiding and persistence

### Data Flow

```
Keyboard → pynput.Listener → KeyListener.on_press()
    → LogManager.buffer.append(key)
    → [buffer full?] → CryptoEngine.encrypt(buffer) → write to .klp file
    → [timer expired?] → CryptoEngine.encrypt(buffer) → Exfiltrator.send()
```

### Encryption Design

AES-256-CBC with random IV per file. Each encrypted file:
- 4-byte magic header (`KLP1`)
- 16-byte IV (os.urandom)
- Ciphertext (padded to AES block size)
- 32-byte HMAC-SHA256 (key = encrypt_key, covers magic + IV + ciphertext)

Chosen over AES-GCM for backward compatibility with older OpenSSL versions.

### Configuration

Config sources (lower number = higher priority):
1. CLI flags
2. Environment variables (`KLP_*`)
3. Config file (`config.yaml`)
4. Defaults

The `ConfigManager` merges these dictionaries in order. No validation beyond type coercion.

## Stealth Implementation

### Windows
- `CREATE_NO_WINDOW` flag via `subprocess.STARTUPINFO`
- Registry `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` for persistence
- Process name spoofing requires DLL injection — not implemented

### Linux
- `os.fork()` + `setsid()` for daemonization
- `prctl(PR_SET_NAME, "kworker/0:0")` for process name
- Cron `@reboot` entry for persistence
- Hides log directory with dot prefix

### macOS
- LaunchAgent plist in `~/Library/LaunchAgents/`
- `setproctitle` for name spoofing (requires `setproctitle` package)
- Hides log files with dot prefix

## Performance

- CPU: < 0.5% on modern hardware during logging
- Memory: ~15MB steady-state (includes Python runtime overhead)
- Disk: ~2KB per 1000 keystrokes (encrypted)
- Network exfiltration: one POST request per interval (configurable)

## Testing

100 mock-based tests — no actual keylogging occurs:
- KeyListener buffer management and overflow
- CryptoEngine encrypt/decrypt round-trips
- LogManager file rotation and naming
- Exfiltrator webhook POST (mocked requests)
- Exfiltrator SMTP send (mocked smtplib)
- ConfigManager merge logic
- StealthManager platform detection
- Edge cases: empty buffers, invalid keys, network failures
- Persistence mechanism installation/removal

## Limitations

1. **Linux key capture requires root.** The pynput library needs access to `/dev/input/*`. Alternative: X11 testing extension.
2. **No clipboard monitoring.** This misses a huge attack surface (password managers).
3. **Webhook exfil is synchronous.** A slow C2 can block the logging thread.
4. **Stealth is shallow.** Any competent EDR will catch us. This is for opportunistic targets.
5. **Windows process hiding is nonexistent.** The "stealth" flag just hides the console window.

## Future Work

- Clipboard monitoring via pyperclip
- Screenshot capture on heuristics (login page detection)
- Encrypted C2 channel using custom protocol (not plain HTTPS)
- Kernel-level keylogging (kbd driver filter) — for Windows, this is a kernel driver. Separate project.
