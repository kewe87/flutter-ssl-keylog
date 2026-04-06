#!/usr/bin/env python3
"""
Capture TLS session keys from DJI Home Flutter app via Frida.

Prerequisites:
  - ADB connected to tablet (adb connect <ip>:<port>)
  - ADB port forwarded: adb forward tcp:27042 tcp:27042
  - frida-server running on device as root
  - pip install frida frida-tools

Usage:
  python run_keylog.py [--spawn]

Keys are saved to keylog.txt (NSS keylog format).
Capture traffic with tcpdump on device, then decrypt in Wireshark.
"""

import sys
import time
import argparse
import frida
from pathlib import Path

PACKAGE = "com.dji.home"
SCRIPT_PATH = Path(__file__).parent / "keylog_hook.js"
KEYLOG_FILE = Path(__file__).parent / "keylog.txt"
FRIDA_HOST = "127.0.0.1:27042"


def on_message(message, data):
    mtype = message.get("type", "")
    if mtype == "send":
        payload = message["payload"]
        if isinstance(payload, dict) and payload.get("type") == "keylog":
            line = payload["line"]
            with open(KEYLOG_FILE, "a") as f:
                f.write(line + "\n")
            print(f"[KEY #{payload['count']}] {line}", flush=True)
        elif isinstance(payload, dict) and payload.get("type") == "secret_no_random":
            print(f"[SECRET] {payload['label']} ??? {payload['secret']}", flush=True)
        else:
            print(f"[frida] {payload}", flush=True)
    elif mtype == "error":
        print(f"[error] {message.get('stack', message.get('description', message))}", flush=True)
    elif mtype == "log":
        print(f"{message.get('payload', '')}", flush=True)
    else:
        print(f"[{mtype}] {message}", flush=True)


def main():
    parser = argparse.ArgumentParser(description="DJI Home TLS KeyLog extractor")
    parser.add_argument("--spawn", action="store_true", help="Spawn app (default: attach to running)")
    parser.add_argument("--host", default=FRIDA_HOST, help=f"Frida host (default: {FRIDA_HOST})")
    args = parser.parse_args()

    print(f"[*] Connecting to {args.host}...", flush=True)
    device = frida.get_device_manager().add_remote_device(args.host)
    print(f"[*] Device: {device.name}", flush=True)

    target_pid = None
    if not args.spawn:
        for proc in device.enumerate_processes():
            if PACKAGE in (proc.identifier if hasattr(proc, 'identifier') else proc.name.lower()):
                target_pid = proc.pid
                print(f"[*] Found {proc.name} (PID {proc.pid})", flush=True)
                break

    if not target_pid:
        print(f"[*] Spawning {PACKAGE}...", flush=True)
        target_pid = device.spawn([PACKAGE])
        spawned = True
    else:
        spawned = False

    print(f"[*] Attaching to PID {target_pid}...", flush=True)
    session = device.attach(target_pid)

    js_code = SCRIPT_PATH.read_text(encoding="utf-8")
    wrapper = "var _origLog = console.log;\nconsole.log = function() { var msg = Array.prototype.slice.call(arguments).join(' '); send(msg); };\n" + js_code
    script = session.create_script(wrapper, runtime="v8")
    script.on("message", on_message)
    script.load()
    print(f"[*] Script injected!", flush=True)

    if spawned:
        device.resume(target_pid)

    print(f"[*] Keys will be saved to {KEYLOG_FILE}", flush=True)
    print(f"[*] Press Ctrl+C to stop.\n", flush=True)

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[*] Detaching...", flush=True)
        session.detach()


if __name__ == "__main__":
    main()
