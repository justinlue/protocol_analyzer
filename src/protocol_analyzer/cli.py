from __future__ import annotations

import argparse
import io
import os
import sys

from .analysis import Analysis
from .errors import PaError, SessionError
from .filters import Filters, csv_set, int_set, time_range
from .info import capture_info, format_info
from .output import jsonl_line, table_line
from .registry import REGISTRY
from .session import load_session, session_from_args


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pa", description="Decode CAN/CANopen and proprietary UART captures.")
    sub = parser.add_subparsers(dest="command", required=True)

    d = sub.add_parser("decode", help="decode a capture into messages")
    d.add_argument("capture", nargs="?", help="capture file (.log, .asc, .bin, .hex, .txt)")
    d.add_argument("--decoder", help="decoder spec: can, canopen, uart:<definition.yaml>")
    d.add_argument("--eds", action="append", metavar="NODE=PATH",
                   help="EDS/DCF file for one CANopen node (repeatable)")
    d.add_argument("--session", help="session YAML binding channels to decoders")
    d.add_argument("--format", choices=["table", "jsonl"], default="table")
    d.add_argument("--abs", action="store_true", help="show absolute timestamps")
    d.add_argument("--id", type=int_set, default=set(), help="CAN ids, comma-separated (0x181,0x201)")
    d.add_argument("--node", type=int_set, default=set(), help="CANopen node ids, comma-separated")
    d.add_argument("--service", type=csv_set, default=set(),
                   help="message names, comma-separated (sdo,emcy,get_info)")
    d.add_argument("--channel", type=csv_set, default=set(), help="channels, comma-separated")
    d.add_argument("--errors-only", action="store_true", help="only messages with an error diagnostic")
    d.add_argument("--time", type=time_range, default=(None, None), metavar="START:END",
                   help="time window in seconds, same basis as the display")
    d.set_defaults(func=cmd_decode)

    i = sub.add_parser("info", help="summarize a capture")
    i.add_argument("capture")
    i.set_defaults(func=cmd_info)

    ds = sub.add_parser("decoders", help="list built-in decoders")
    ds.set_defaults(func=cmd_decoders)
    return parser


def cmd_decode(args: argparse.Namespace) -> int:
    if args.session:
        if args.decoder or args.eds:
            raise SessionError("--decoder/--eds cannot be combined with --session")
        session = load_session(args.session)
        if args.capture:
            session.capture = session.base_dir / args.capture
    elif not args.capture:
        raise SessionError("decode needs a capture file or --session")
    else:
        session = session_from_args(args.capture, args.decoder, args.eds)
    filters = Filters(ids=args.id, nodes=args.node, services=args.service, channels=args.channel,
                      errors_only=args.errors_only, time_range=args.time)
    fmt = jsonl_line if args.format == "jsonl" else table_line
    analysis = Analysis(session)
    for msg in analysis.messages():
        if filters.matches(msg, analysis.t0, args.abs):
            print(fmt(msg, analysis.t0, args.abs))
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    print(format_info(capture_info(args.capture)))
    return 0


def cmd_decoders(args: argparse.Namespace) -> int:
    for info in REGISTRY.values():
        print(f"{info.usage:<26} {info.description}")
    return 0


def _utf8_stdout() -> None:
    # A cp1252 console or redirect cannot encode units like °C; never crash on output.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError, io.UnsupportedOperation):
        pass


def main(argv: list[str] | None = None) -> int:
    _utf8_stdout()
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except PaError as exc:
        print(f"pa: error: {exc}", file=sys.stderr)
        return 2
    except BrokenPipeError:  # output piped into e.g. `head`, which exited early
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 0
