"""
tool_cli.py - CLI for keygen / hide / extract on top of the facade.

Currently imports facade_mock (MOCK, no real crypto or audio). When the real
facade is integrated on Day 4, only the import line below changes.

Usage (cmd, venv active):
  python code\\tool_cli.py keygen --level 768 --out-dir tmp_test\\keys
  python code\\tool_cli.py hide --carrier C --file F --ek EK --level 768 --mode pqc
  python code\\tool_cli.py extract --stego S --dk DK
Exit code 0 on success, 1 on a clean error, 2 on bad arguments.
"""
import argparse
import sys

import facade_mock as facade  # swap for the real facade on integration day

MODE_CHOICES = sorted(facade.MODES)


def build_parser():
    ap = argparse.ArgumentParser(prog="tool_cli.py")
    sub = ap.add_subparsers(dest="cmd", required=True)

    k = sub.add_parser("keygen", help="generate the receiver's ek / dk files")
    k.add_argument("--level", type=int, choices=facade.LEVELS, default=768)
    k.add_argument("--out-dir", required=True)

    h = sub.add_parser("hide", help="hide a file in a carrier")
    h.add_argument("--carrier", required=True)
    h.add_argument("--file", required=True)
    h.add_argument("--ek", required=True)
    h.add_argument("--level", type=int, choices=facade.LEVELS, default=768)
    h.add_argument("--mode", choices=MODE_CHOICES, default="pqc")
    h.add_argument("--qkd-key-file", default=None,
                   help="simulated-QKD key file (hybrid-qkdsim only, simulation)")
    h.add_argument("--out", default=None)

    e = sub.add_parser("extract", help="extract a hidden file")
    e.add_argument("--stego", required=True)
    e.add_argument("--dk", required=True)
    e.add_argument("--qkd-key-file", default=None)
    e.add_argument("--out", default=None)
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if args.cmd == "keygen":
            ek, dk = facade.keygen(args.level, args.out_dir)
            print("ek:", ek)
            print("dk:", dk)
        elif args.cmd == "hide":
            out = facade.hide(args.carrier, args.file, args.ek, args.level,
                              args.mode, qkd_key_file=args.qkd_key_file, out=args.out)
            print("stego written:", out)
        else:
            out = facade.extract(args.stego, args.dk,
                                 qkd_key_file=args.qkd_key_file, out=args.out)
            print("extracted:", out)
    except facade.FacadeError as err:
        print("ERROR:", err)
        return 1
    except OSError as err:
        print("ERROR: file problem -", err)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
