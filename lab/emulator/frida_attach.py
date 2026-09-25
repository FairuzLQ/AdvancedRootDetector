"""Attach Frida to a PID on the USB/emulator device and stay attached for N seconds."""
import sys
import time

import frida

pid, seconds = int(sys.argv[1]), int(sys.argv[2])
device = frida.get_usb_device(timeout=30)
session = device.attach(pid)
# A trivial hook so the agent is fully initialised (JS runtime threads running).
script = session.create_script("setTimeout(function () { send('attached'); }, 0);")
script.on("message", lambda msg, data: print("frida:", msg, flush=True))
script.load()
time.sleep(seconds)
session.detach()
