"""Attach Frida to a PID on the USB/emulator device and stay attached for N seconds.

Usage: frida_attach.py <pid> <seconds> [hook]
  hook: also place a (no-op) Interceptor hook on libc open(), to verify that the
        library's inline-hook check sees the patched prologue.
"""
import sys
import time

import frida

pid, seconds = int(sys.argv[1]), int(sys.argv[2])
hook = len(sys.argv) > 3 and sys.argv[3] == "hook"

SOURCE = "setTimeout(function () { send('attached'); }, 0);"
if hook:
    SOURCE += """
var openPtr = Process.getModuleByName('libc.so').getExportByName('open');
Interceptor.attach(openPtr, { onEnter: function (args) {} });
send('hooked open');
"""

device = frida.get_usb_device(timeout=30)
session = device.attach(pid)
script = session.create_script(SOURCE)
script.on("message", lambda msg, data: print("frida:", msg, flush=True))
script.load()
time.sleep(seconds)
session.detach()
