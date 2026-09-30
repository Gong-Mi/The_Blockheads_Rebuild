#!/usr/bin/env python3
"""Trace Objective-C selector dispatches in The Blockheads via Frida.

Captures (caller_addr, selector) pairs for objc_msgSend calls whose caller
is inside libApplication.so, and writes them to a TSV file.

Usage:
  python3 trace_selectors_frida.py <output.tsv> [--duration 60]
"""
from __future__ import annotations

import argparse
import frida
import sys
import time
from pathlib import Path

PACKAGE = "com.noodlecake.blockheads"

JS_CODE = r"""
'use strict';

var appBase = null;
var appEnd = null;

// Find libApplication.so mapping
Process.enumerateRanges('r-x').forEach(function (range) {
    if (range.file && range.file.path && range.file.path.indexOf('libApplication.so') !== -1) {
        if (appBase === null || range.base < appBase) {
            appBase = range.base;
        }
        var end = range.base.add(range.size);
        if (appEnd === null || end > appEnd) {
            appEnd = end;
        }
    }
});

if (appBase === null) {
    send({type: 'error', message: 'libApplication.so not found in memory'});
} else {
    send({type: 'info', message: 'libApplication.so base=' + appBase});

    // Resolve objc_msgSend
    var msgSend = null;
    try {
        msgSend = Module.getExportByName(null, 'objc_msgSend');
    } catch (e) {
        // Try libSystem.so
        try {
            msgSend = Module.getExportByName('libSystem.so', 'objc_msgSend');
        } catch (e2) {
            send({type: 'error', message: 'objc_msgSend not found'});
        }
    }

    if (msgSend !== null) {
        send({type: 'info', message: 'objc_msgSend at ' + msgSend});

        Interceptor.attach(msgSend, {
            onEnter: function (args) {
                // ARM32: r0=receiver, r1=selector
                // On ARM64 the ABI is different, but this game is ARMv7
                var lr = this.context.lr;
                if (lr >= appBase && lr < appEnd) {
                    var sel = args[1];
                    var selName = '';
                    try {
                        selName = sel.readCString();
                    } catch (e) {
                        selName = '<unreadable>';
                    }
                    send({
                        type: 'call',
                        caller: lr.sub(appBase).toString(),
                        selector: selName
                    });
                }
            }
        });
    }
}
"""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--duration", type=int, default=60)
    parser.add_argument("--package", default=PACKAGE)
    parser.add_argument("--host", default="127.0.0.1:27042",
                        help="frida-server host (default: local root frida-server)")
    args = parser.parse_args()

    try:
        manager = frida.get_device_manager()
        device = manager.add_remote_device(args.host)
    except Exception as e:
        print(f"error: cannot connect to frida-server at {args.host}: {e}", file=sys.stderr)
        return 1

    target: int | str = int(args.package) if args.package.isdigit() else args.package
    try:
        session = device.attach(target)
    except Exception as e:
        print(f"error: cannot attach to {args.package}: {e}", file=sys.stderr)
        return 1

    calls = []
    errors = []

    def on_message(message, data):
        if message["type"] == "send":
            payload = message["payload"]
            if payload["type"] == "call":
                calls.append(payload)
            elif payload["type"] == "error":
                errors.append(payload["message"])
            elif payload["type"] == "info":
                print(f"[frida] {payload['message']}", file=sys.stderr)
        elif message["type"] == "error":
            errors.append(message["description"])

    script = session.create_script(JS_CODE)
    script.on("message", on_message)
    script.load()

    print(f"tracing for {args.duration} seconds...", file=sys.stderr)
    time.sleep(args.duration)
    session.detach()

    if errors:
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as f:
        f.write("caller_offset\tselector\n")
        for c in calls:
            f.write(f"{c['caller']}\t{c['selector']}\n")

    print(f"calls={len(calls)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
