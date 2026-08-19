"""Command-line interface.

Subcommands:

    adapter   manage monitor mode / injection test / reset
    scan      discover nearby APs
    capture   autonomous handshake+PMKID capture (scan -> deauth -> verify -> learn)
    pmkid     capture/convert PMKIDs
    verify    strongly verify a capture is a genuine 4-way handshake
    tools     report which Kali tools are installed / missing
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .config import load_config
from .constants import (
    EXIT_AUTH_DENIED,
    EXIT_CAPTURE_FAILED,
    EXIT_NOT_ROOT,
    EXIT_OK,
    EXIT_TOOL_MISSING,
    EXIT_VERIFY_FAILED,
)
from .core.engine import Engine, exit_code_for
from .exceptions import (
    AuthorizationDeniedError,
    HandshakerError,
    NotRootError,
    ToolNotFoundError,
)
from .utils.logging import configure_logging


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="handshaker",
        description="Autonomous WiFi 4-way handshake & PMKID capturer "
                    "(authorized security testing only; capture only — no cracking).",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("-c", "--config", help="path to config.yaml")
    p.add_argument("-i", "--interface", help="wireless interface (default: auto-detect)")
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging")

    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("adapter", help="manage monitor mode / injection test / reset")

    scan = sub.add_parser("scan", help="discover nearby APs")
    scan.add_argument("--duration", type=int, default=None, help="scan seconds")

    cap = sub.add_parser("capture", help="autonomous capture (scan+deauth+verify+learn)")
    cap.add_argument("--scan-duration", type=int, default=None)

    pmkid = sub.add_parser("pmkid", help="capture or convert PMKIDs")
    pmkid.add_argument("--bssid", help="target BSSID")
    pmkid.add_argument("--channel", type=int, help="target channel")
    pmkid.add_argument("--convert", metavar="FILE", help="convert existing capture to 22000")

    verify = sub.add_parser("verify", help="verify a capture is a 4-way handshake")
    verify.add_argument("file", help="capture file (.pcap/.pcapng)")

    sub.add_parser("tools", help="report installed/missing Kali tools")
    return p


def _report_tools(engine: Engine) -> int:
    rep = engine.tool_report()
    print("Available tools:")
    for t in rep["available"]:
        print(f"  [x] {t}")
    print("\nMissing tools:")
    for t in rep["missing"]:
        print(f"  [ ] {t}")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    config = load_config(args.config)
    configure_logging("DEBUG" if args.verbose else config["general"]["log_level"])

    try:
        engine = Engine(config)

        if args.command == "tools":
            return _report_tools(engine)

        if args.command == "adapter":
            return _cmd_adapter(engine, args)

        if args.command == "scan":
            return _cmd_scan(engine, args)

        if args.command == "capture":
            return _cmd_capture(engine, args)

        if args.command == "pmkid":
            return _cmd_pmkid(engine, args)

        if args.command == "verify":
            return _cmd_verify(engine, args)

    except HandshakerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        if isinstance(exc, NotRootError):
            return EXIT_NOT_ROOT
        if isinstance(exc, AuthorizationDeniedError):
            return EXIT_AUTH_DENIED
        if isinstance(exc, ToolNotFoundError):
            return EXIT_TOOL_MISSING
        return EXIT_CAPTURE_FAILED
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130

    return EXIT_OK


def _cmd_adapter(engine: Engine, args) -> int:
    engine.check_root()
    iface = engine.adapter.select_interface(args.interface)
    print(f"Interface: {iface}")
    print(f"Monitor mode: {engine.adapter.is_monitor(iface)}")
    if not engine.adapter.is_monitor(iface):
        mon = engine.adapter.enable_monitor(iface)
        print(f"Enabled monitor mode: {mon}")
    if engine.config["adapter"]["check_injection"]:
        print(f"Injection working: {engine.adapter.check_injection(iface)}")
    return EXIT_OK


def _cmd_scan(engine: Engine, args) -> int:
    engine.check_root()
    iface = engine.adapter.select_interface(args.interface)
    result = engine.scan(iface, args.duration)
    print(f"Found {len(result.aps)} access point(s):\n")
    for ap in sorted(result.aps.values(), key=lambda a: a.power, reverse=True):
        clients = len(result.clients_of(ap.bssid))
        print(f"  {ap.bssid}  ch={ap.channel:>3}  {ap.power:>4}dBm  "
              f"{ap.security_label:>4}  clients={clients}  {ap.essid or '(hidden)'}")
    return EXIT_OK


def _cmd_capture(engine: Engine, args) -> int:
    iface = engine.adapter.select_interface(args.interface)
    stats = None
    exc = None
    try:
        stats = engine.run_auto(iface, args.scan_duration)
    except HandshakerError as e:
        exc = e
        print(f"error: {e}", file=sys.stderr)

    if stats is not None:
        print("\n" + "=" * 60)
        print(" RUN SUMMARY")
        print("=" * 60)
        print(f"  targets scanned   : {stats.targets_scanned}")
        print(f"  targets attacked  : {stats.targets_attacked}")
        print(f"  handshakes verified: {stats.handshakes_captured}")
        print(f"  handshakes rejected: {stats.handshakes_rejected}")
        print(f"  PMKIDs captured   : {stats.pmkids_captured}")
        if stats.verified_files:
            print("\n  Stored handshakes:")
            for f in stats.verified_files:
                print(f"    - {f}")
        if stats.failures:
            print("\n  Failures (recorded truthfully):")
            for f in stats.failures:
                print(f"    - {f}")
    return exit_code_for(stats, exc)


def _cmd_pmkid(engine: Engine, args) -> int:
    engine.check_root()
    if args.convert:
        out = engine.pmkid.convert(args.convert)
        print(f"Converted -> {out}" if out else "No 22000 lines produced.")
        return EXIT_OK
    if not args.bssid or not args.channel:
        print("error: --bssid and --channel are required for PMKID capture.", file=sys.stderr)
        return EXIT_CAPTURE_FAILED
    iface = engine.adapter.select_interface(args.interface)
    out = engine.pmkid.capture(iface, args.bssid, args.channel)
    print(f"PMKID capture -> {out}" if out else "No PMKID captured.")
    return EXIT_OK


def _cmd_verify(engine: Engine, args) -> int:
    report = engine.verify(args.file)
    import json
    print(json.dumps(report.to_dict(), indent=2))
    return EXIT_OK if report.passed else EXIT_VERIFY_FAILED


if __name__ == "__main__":
    raise SystemExit(main())
