# DJI Home Flutter TLS KeyLog Extractor

Extract TLS session keys from the DJI Home Android app (Flutter/BoringSSL) using Frida.  
Enables decryption of HTTPS traffic in Wireshark **without** modifying the APK or bypassing certificate pinning.

## How it works

The DJI Home app uses Flutter with statically linked BoringSSL. Standard SSL bypass methods fail because:
- No exported SSL symbols in `libflutter.so`
- Standard ARM64 byte patterns don't match DJI's custom build
- reFlutter APK patching crashes due to AppGuard anti-tampering

This tool takes a different approach: it hooks BoringSSL's internal `ssl_log_secret` function to extract TLS session keys in [NSS Key Log Format](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format). Combined with a packet capture, Wireshark can decrypt all HTTPS traffic.

### Offsets (DJI Home 1.5.15 / libflutter.so MD5: 168d74f31dd1fa4f16b0805eb05d8b10)

| Symbol | Offset | Notes |
|--------|--------|-------|
| `ssl_log_secret` stub | `0x9b4d6c` | `MOV X0,X19; B <real_impl>` |
| `ssl_log_secret` real | `0x6cdff8` | `FUN_007cdff8` (240 bytes) |
| `client_random` | `[SSL+0x30]+0x30` | 32 bytes |
| TLS 1.3 HS key logger | `0x6d3cc0` | References `CLIENT/SERVER_HANDSHAKE_TRAFFIC_SECRET` |
| TLS 1.3 app key logger | `0x6d3d5c` | References `CLIENT/SERVER_TRAFFIC_SECRET_0`, `EXPORTER_SECRET` |
| TLS 1.2 key logger | `0x6c3514` | References `CLIENT_RANDOM` |

These offsets were found using Ghidra headless analysis with custom scripts (see `ghidra_scripts/`).

## Requirements

- **Rooted Android device** with DJI Home app installed
- **ADB** (Android Debug Bridge) connected to the device
- **frida-server** matching your Frida version, running as root on the device
- **Python 3.8+** with `frida` and `frida-tools` packages
- **Wireshark/tshark** for decryption
- **tcpdump** on the device (usually pre-installed on rooted devices)

```bash
pip install frida frida-tools
```

## Setup

### 1. Connect ADB

```bash
# WiFi ADB
adb connect <tablet-ip>:<port>

# Verify
adb devices
```

### 2. Push and start frida-server

```bash
# Download matching version from https://github.com/frida/frida/releases
# For ARM64 device:
adb push frida-server-<version>-android-arm64 /data/local/tmp/frida-server
adb shell "su -c 'chmod 755 /data/local/tmp/frida-server'"
adb shell "su -c '/data/local/tmp/frida-server -l 0.0.0.0:27042 -D &'"
```

### 3. Forward Frida port

```bash
adb forward tcp:27042 tcp:27042
```

## Usage

### Capture session keys + traffic

```bash
# Terminal 1: Start tcpdump on device
adb shell "su -c 'tcpdump -i any -w /sdcard/capture.pcap'"

# Terminal 2: Start key extraction
python run_keylog.py

# Use the DJI Home app (start cleaning, change settings, etc.)
# Press Ctrl+C in both terminals when done

# Pull the capture
adb pull /sdcard/capture.pcap .
```

### Decrypt in Wireshark

1. Open `capture.pcap` in Wireshark
2. Go to **Edit > Preferences > Protocols > TLS**
3. Set **(Pre)-Master-Secret log filename** to your `keylog.txt`
4. Click OK — TLS traffic is now decrypted
5. Filter: `http` to see API requests

### CLI decryption with tshark

```bash
# List all HTTP requests
tshark -r capture.pcap -o tls.keylog_file:keylog.txt -Y "http" \
  -T fields -e http.request.method -e http.request.uri -e http.host

# Show full request/response for a specific frame
tshark -r capture.pcap -o tls.keylog_file:keylog.txt -Y "frame.number == 1234" -V
```

## Adapting to other Flutter versions

If the DJI Home app is updated, the offsets will change. To find new offsets:

1. Extract `libflutter.so` from the APK
2. Open in Ghidra, let it analyze
3. Search for the string `CLIENT_HANDSHAKE_TRAFFIC_SECRET`
4. Find xrefs to that string — the function containing the xref calls `ssl_log_secret`
5. The common callee of all TLS key logger functions is `ssl_log_secret`
6. Inside `ssl_log_secret`, look for `[param_1+0x30]+0x30` ��� that's the client_random access pattern

Ghidra headless scripts for automated offset discovery are in the `ghidra_scripts/` directory.
