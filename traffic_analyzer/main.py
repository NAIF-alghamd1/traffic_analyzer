#!/usr/bin/env python3
"""
HTTP/HTTPS Traffic Analyzer - entry point.

Defensive traffic-analysis tool for authorized testing environments.
Starts a local mitmproxy instance (capture layer, background thread)
and a PyQt6 UI (main thread) that visualizes what it captures.

Usage:
    python main.py [--port 8080]

On first run, point your browser/app's proxy settings at
127.0.0.1:<port> and, if you want HTTPS content visibility (not just
TLS metadata), install mitmproxy's local CA certificate from
~/.mitmproxy/mitmproxy-ca-cert.pem into your OS/browser trust store.
This is optional -- the tool works in TLS-metadata-only mode without it.
"""
from __future__ import annotations

import argparse
import asyncio
import queue
import sys
import threading

from mitmproxy import options
from mitmproxy.tools import dump

from capture.proxy_addon import TrafficCaptureAddon


def run_proxy_thread(port: int, event_queue: "queue.Queue", ready_event: threading.Event,
                      stop_event: threading.Event) -> None:
    """Runs mitmproxy's own asyncio event loop in a background thread,
    isolated from Qt's event loop on the main thread.
    """
    async def _main() -> None:
        opts = options.Options(listen_host="127.0.0.1", listen_port=port)
        master = dump.DumpMaster(opts, with_termlog=False, with_dumper=False)
        master.addons.add(TrafficCaptureAddon(event_queue))

        ready_event.set()
        try:
            await master.run()
        finally:
            master.shutdown()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    async def _watch_stop() -> None:
        while not stop_event.is_set():
            await asyncio.sleep(0.25)
        loop.stop()

    try:
        loop.create_task(_watch_stop())
        loop.run_until_complete(_main())
    finally:
        loop.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="HTTP/HTTPS Traffic Analyzer")
    parser.add_argument("--port", type=int, default=8080,
                         help="Local proxy port (default: 8080)")
    parser.add_argument("--no-gui", action="store_true",
                         help="Run capture only, no UI (for scripting/tests)")
    args = parser.parse_args()

    event_queue: "queue.Queue" = queue.Queue()
    ready_event = threading.Event()
    stop_event = threading.Event()

    proxy_thread = threading.Thread(
        target=run_proxy_thread,
        args=(args.port, event_queue, ready_event, stop_event),
        daemon=True,
    )
    proxy_thread.start()
    ready_event.wait(timeout=10)

    print(f"[traffic-analyzer] Proxy listening on 127.0.0.1:{args.port}")
    print("[traffic-analyzer] Point your browser/app's HTTP(S) proxy at the address above.")
    print("[traffic-analyzer] For HTTPS content visibility, install the CA cert from "
          "~/.mitmproxy/mitmproxy-ca-cert.pem in your own trust store (optional).")

    if args.no_gui:
        try:
            while proxy_thread.is_alive():
                proxy_thread.join(timeout=1)
        except KeyboardInterrupt:
            pass
        finally:
            stop_event.set()
        return 0

    # Import UI lazily so `--no-gui` mode doesn't require PyQt6 to be
    # installed at all (useful for headless/CI capture-only usage).
    from PyQt6.QtWidgets import QApplication
    from ui.main_window import MainWindow

    app = QApplication(sys.argv)
    window = MainWindow(event_queue=event_queue, proxy_port=args.port)
    window.show()

    exit_code = app.exec()
    stop_event.set()
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
