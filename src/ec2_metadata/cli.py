from __future__ import annotations

import argparse
import json
from collections.abc import Sequence

from ec2_metadata import ec2_metadata

gettable_names = {name for name in dir(ec2_metadata) if not name.startswith("_")} - {
    "clear-all"
}


def validate_name(name: str) -> str:
    if name not in gettable_names and name.replace("-", "_") not in gettable_names:
        raise argparse.ArgumentTypeError(
            f"Invalid metadata name: {name}. Must be one of: {', '.join(sorted(gettable_names))}"
        )
    return name


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(
        dest="command", help="Available commands", required=True
    )

    get_parser = subparsers.add_parser(
        "get",
        help="Get a single metadata value.",
    )
    get_parser.add_argument(
        "name",
        help="The name of the metadata value to retrieve.",
        type=validate_name,
    )
    get_parser.add_argument(
        "-n",
        help="Do not print a newline after the value.",
        action="store_false",
        dest="newline",
    )

    json_parser = subparsers.add_parser(
        "json",
        help="Get selected metadata values as JSON.",
    )
    json_parser.add_argument(
        "names",
        help="The names of the metadata values to retrieve.",
        nargs="+",
        type=validate_name,
    )

    args = parser.parse_args(argv)

    if args.command == "get":
        return get_subcommand(name=args.name, newline=args.newline)
    elif args.command == "json":
        return json_subcommand(names=args.names)
    else:  # pragma: no cover
        # Unreachable
        raise NotImplementedError(f"Command {args.command} does not exist.")


def get_subcommand(name: str, newline: bool) -> int:
    name = name.replace("-", "_")
    print(
        getattr(ec2_metadata, name),
        end="" if not newline else "\n",
        flush=True,
    )
    return 0


def json_subcommand(names: Sequence[str]) -> int:
    data = {name: getattr(ec2_metadata, name.replace("-", "_")) for name in names}
    print(json.dumps(data, indent=2))
    return 0
