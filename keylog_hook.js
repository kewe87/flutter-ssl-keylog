/**
 * Frida: TLS KeyLog extraction from Flutter/BoringSSL (DJI Home app)
 *
 * Hooks ssl_log_secret in libflutter.so to capture TLS session keys
 * in NSS keylog format. Combined with a pcap, Wireshark can decrypt
 * all HTTPS traffic without modifying the APK or bypassing cert pinning.
 *
 * Offsets found via Ghidra analysis of libflutter.so (DJI Home 1.5.15):
 *   ssl_log_secret stub:  0x9b4d6c  (MOV X0,X19; B real_impl)
 *   real ssl_log_secret:  0x6cdff8  (FUN_007cdff8)
 *   client_random:        [SSL+0x30]+0x30, 32 bytes
 *
 * Keys are sent to the Python host via send() for local file storage.
 *
 * Usage:
 *   python run_keylog.py
 */

var keysLogged = 0;
var seenKeys = {};

function writeKeylog(line) {
    if (seenKeys[line]) return;
    seenKeys[line] = true;
    keysLogged++;
    send({ type: "keylog", line: line, count: keysLogged });
    console.log("[KEY #" + keysLogged + "] " + line);
}

function bytesToHex(buf) {
    var bytes = new Uint8Array(buf);
    var hex = "";
    for (var i = 0; i < bytes.length; i++) {
        hex += (bytes[i] < 16 ? "0" : "") + bytes[i].toString(16);
    }
    return hex;
}

function main() {
    var m = Process.findModuleByName("libflutter.so");
    if (!m) {
        console.log("[!] libflutter.so not loaded yet");
        return false;
    }
    console.log("[*] libflutter.so base=" + m.base);

    // ssl_log_secret stub at 0x9b4d6c: MOV X0,X19 + B <real_impl>
    var stubAddr = m.base.add(0x9b4d6c);

    // Decode the B instruction to find real ssl_log_secret
    var bInstr = stubAddr.add(4).readU32();
    var bImm26 = bInstr & 0x3FFFFFF;
    if (bImm26 & 0x2000000) bImm26 = bImm26 - 0x4000000;
    var realAddr = stubAddr.add(4).add(bImm26 * 4);
    console.log("[*] Real ssl_log_secret at " + realAddr +
        " (offset 0x" + realAddr.sub(m.base).toInt32().toString(16) + ")");

    // Hook real ssl_log_secret
    // After stub's MOV X0,X19: x0=SSL*, x1=label, x2=secret, x3=secret_len
    Interceptor.attach(realAddr, {
        onEnter: function(args) {
            try {
                var ssl = args[0];
                var label = args[1].readUtf8String();
                var secretLen = args[3].toInt32();

                if (!label || secretLen <= 0 || secretLen > 256) {
                    this.skip = true;
                    return;
                }
                this.skip = false;
                this.label = label;
                this.secret = bytesToHex(args[2].readByteArray(secretLen));
                this.clientRandom = extractClientRandom(ssl);
            } catch(e) {
                console.log("[!] Hook error: " + e.message);
                this.skip = true;
            }
        },
        onLeave: function(ret) {
            if (this.skip) return;
            if (this.clientRandom) {
                writeKeylog(this.label + " " + this.clientRandom + " " + this.secret);
            } else {
                console.log("[!] " + this.label + " - no client_random");
                send({ type: "secret_no_random", label: this.label, secret: this.secret });
            }
        }
    });

    // Also hook the tail-call variant (same function, called via B not BL)
    var tailCallAddr = m.base.add(0x6cdff8);
    if (!realAddr.equals(tailCallAddr)) {
        console.log("[*] Also hooking tail-call at " + tailCallAddr);
        Interceptor.attach(tailCallAddr, {
            onEnter: function(args) {
                try {
                    var label = args[1].readUtf8String();
                    var secretLen = args[3].toInt32();
                    if (!label || secretLen <= 0 || secretLen > 256) { this.skip = true; return; }
                    this.skip = false;
                    this.label = label;
                    this.secret = bytesToHex(args[2].readByteArray(secretLen));
                    this.clientRandom = extractClientRandom(args[0]);
                } catch(e) { this.skip = true; }
            },
            onLeave: function(ret) {
                if (this.skip) return;
                if (this.clientRandom) {
                    writeKeylog(this.label + " " + this.clientRandom + " " + this.secret);
                }
            }
        });
    }

    console.log("[+] Hooks installed! Waiting for TLS handshakes...\n");
    return true;
}

function extractClientRandom(sslPtr) {
    // From Ghidra decompilation of ssl_log_secret:
    //   client_random = [SSL+0x30] + 0x30, length 0x20 (32 bytes)
    try {
        var s3 = sslPtr.add(0x30).readPointer();
        if (!s3.isNull() && s3.compare(ptr(0x10000)) > 0) {
            return bytesToHex(s3.add(0x30).readByteArray(32));
        }
    } catch(e) {}
    return null;
}

var attempts = 0;
var timer = setInterval(function() {
    attempts++;
    if (main() || attempts > 15) {
        clearInterval(timer);
        if (attempts > 15) console.log("[!] libflutter.so not loaded after 30s");
    }
}, 2000);
