"""Command-line interface for Athar verifiable erasure receipts.

This module provides commands for enrolling subjects, executing erasure sagas,
generating tamper-evident erasure receipts, verifying receipts, querying job
status, and running demonstration scenarios.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

_NOT_IMPLEMENTED = (
    "The '{cmd}' command is not implemented in this MVP: the keystore and vault are "
    "in-memory only, so there is no persistent state for a CLI to operate on.\n"
    "Run the end-to-end flow with 'athar demo', or use the Python API "
    "(athar.erasure.saga.ErasureSaga, athar.receipt.builder.ReceiptBuilder)."
)


def _not_implemented(cmd: str) -> int:
    print(_NOT_IMPLEMENTED.format(cmd=cmd), file=sys.stderr)
    return 2


def cmd_enroll(args: argparse.Namespace) -> int:
    """Not implemented: needs a persistent keystore/vault."""
    return _not_implemented("enroll")


def cmd_erase(args: argparse.Namespace) -> int:
    """Not implemented: needs a persistent keystore/vault."""
    return _not_implemented("erase")


def cmd_receipt(args: argparse.Namespace) -> int:
    """Not implemented: needs a persistent fact log and signing key."""
    return _not_implemented("receipt")


def cmd_status(args: argparse.Namespace) -> int:
    """Not implemented: needs persisted saga jobs."""
    return _not_implemented("status")


def cmd_verify(args: argparse.Namespace) -> int:
    """Verify a receipt using the real standalone verifier."""
    from verifier.verifier import main as verifier_main

    argv = [args.receipt]
    if args.public_key:
        argv += ["--public-key", args.public_key]
    if args.trust_embedded_key:
        argv.append("--trust-embedded-key")
    if args.allow_missing_timestamp:
        argv.append("--allow-missing-timestamp")
    return verifier_main(argv)


def cmd_demo(args: argparse.Namespace) -> int:
    """Run the real end-to-end QuickFin scenario (demo.quickfin)."""
    if args.scenario != "quickfin":
        print(f"Unknown scenario: {args.scenario}", file=sys.stderr)
        return 1
    try:
        from demo.quickfin import run_quickfin_demo
    except ImportError as err:
        print(
            "The demo package is not importable. Run from the repository root "
            f"(pip install -e . ; python -m demo.quickfin). Details: {err}",
            file=sys.stderr,
        )
        return 1
    return run_quickfin_demo(args.receipt_out, args.public_key_out)


def build_parser() -> argparse.ArgumentParser:
    """Build and configure the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="athar",
        description="Athar: Verifiable Erasure Receipts reference implementation CLI "
        "(only verify and demo are functional in this MVP)",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # enroll
    parser_enroll = subparsers.add_parser(
        "enroll", help="Enroll a subject with keys and pseudonym"
    )
    parser_enroll.add_argument(
        "--subject-id", help="Optional explicit pseudonym (defaults to random)"
    )
    parser_enroll.add_argument(
        "--policy", help="Retention policy name to associate", default="default"
    )
    parser_enroll.add_argument(
        "--jurisdiction",
        help="Compliance jurisdiction code (no default; must be chosen explicitly)",
        default=None,
    )
    parser_enroll.add_argument("--output", "-o", help="File path to write enrollment JSON")

    # erase
    parser_erase = subparsers.add_parser("erase", help="Trigger erasure saga for a subject")
    parser_erase.add_argument("--subject-id", required=True, help="Subject pseudonym to erase")
    parser_erase.add_argument(
        "--reason", default="gdpr_article_17", help="Erasure reason/justification"
    )
    parser_erase.add_argument("--manifest-out", help="Path to write the erasure manifest")
    parser_erase.add_argument("--force", action="store_true", help="Bypass non-critical warnings")

    # receipt
    parser_receipt = subparsers.add_parser("receipt", help="Generate a verifiable erasure receipt")
    parser_receipt.add_argument(
        "--job-id", "--saga-id", required=True, help="Completed erasure saga ID"
    )
    parser_receipt.add_argument("--output", "-o", help="Path to write the receipt JSON")

    # verify
    parser_verify = subparsers.add_parser("verify", help="Verify an erasure receipt")
    parser_verify.add_argument("--receipt", "-r", required=True, help="Path to receipt JSON file")
    parser_verify.add_argument(
        "--public-key", help="Path to file with the issuer's hex Ed25519 public key (pinned)"
    )
    parser_verify.add_argument(
        "--trust-embedded-key",
        action="store_true",
        help="Trust the key embedded in the receipt (does NOT authenticate the issuer)",
    )
    parser_verify.add_argument(
        "--allow-missing-timestamp", action="store_true", help="Do not fail if no timestamp token"
    )

    # demo
    parser_demo = subparsers.add_parser("demo", help="Run the QuickFin demonstration scenario")
    parser_demo.add_argument(
        "--scenario", default="quickfin", help="Demo scenario to run (default: quickfin)"
    )
    parser_demo.add_argument("--receipt-out", help="Write the issued receipt JSON to this path")
    parser_demo.add_argument(
        "--public-key-out", help="Write the issuer's hex public key to this path"
    )

    # status
    parser_status = subparsers.add_parser("status", help="Show erasure job status")
    group = parser_status.add_mutually_exclusive_group(required=True)
    group.add_argument("--job-id", help="Erasure job or saga identifier")
    group.add_argument("--subject-id", help="Subject pseudonym identifier")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for the Athar CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 1

    handlers = {
        "enroll": cmd_enroll,
        "erase": cmd_erase,
        "receipt": cmd_receipt,
        "verify": cmd_verify,
        "demo": cmd_demo,
        "status": cmd_status,
    }

    handler = handlers.get(args.command)
    if handler:
        return handler(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
