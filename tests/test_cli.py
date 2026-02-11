from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

# import __main__ for coverage
from ec2_metadata import __main__  # noqa: F401
from ec2_metadata.cli import main

prog_name = (
    f"{Path(sys.executable).name} -m pytest"
    if sys.version_info >= (3, 14) and sys.modules["__main__"].__spec__
    else Path(sys.argv[0]).name
)


class TestMain:
    def test_no_subcommand(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            main([])

        assert excinfo.value.code == 2
        out, err = capsys.readouterr()
        assert err == (
            f"usage: {prog_name} [-h] {{get,json}} ...\n"
            + f"{prog_name}: error: the following arguments are required: command\n"
        )
        assert out == ""

    def test_main_help(self):
        with pytest.raises(SystemExit) as excinfo:
            main(["--help"])

        assert excinfo.value.code == 0

    def test_main_help_subprocess(self):
        proc = subprocess.run(
            [sys.executable, "-m", "ec2_metadata", "--help"],
            check=True,
            capture_output=True,
        )

        if sys.version_info >= (3, 14):
            assert proc.stdout.startswith(
                f"usage: {Path(sys.executable).name} -m ec2_metadata ".encode()
            )
        else:
            assert proc.stdout.startswith(b"usage: __main__.py ")

    def test_get_help_command(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            main(["get", "--help"])
        assert excinfo.value.code == 0

    def test_get_no_name(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            main(["get"])

        assert excinfo.value.code == 2

    def test_get_invalid_name(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            main(["get", "invalid-name!"])

        assert excinfo.value.code == 2
        out, err = capsys.readouterr()
        assert out == ""
        assert err.startswith(
            f"usage: {prog_name} get [-h] [-n] name\n"
            + f"{prog_name} get: error: argument name: Invalid metadata name: invalid-name!. Must be one of: account_id, ami_id, "
        )

    def test_get_valid_name(self, capsys):
        with mock.patch("ec2_metadata.cli.ec2_metadata") as mock_metadata:
            mock_metadata.instance_id = "i-1234567890abcdef0"

            main(["get", "instance-id"])

        out, err = capsys.readouterr()
        assert out == "i-1234567890abcdef0\n"
        assert err == ""

    def test_get_valid_name_no_newline(self, capsys):
        with mock.patch("ec2_metadata.cli.ec2_metadata") as mock_metadata:
            mock_metadata.instance_id = "i-1234567890abcdef0"

            main(["get", "instance-id", "-n"])

        out, err = capsys.readouterr()
        assert out == "i-1234567890abcdef0"
        assert err == ""

    def test_json_help_command(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            main(["json", "--help"])
        assert excinfo.value.code == 0

    def test_json_no_names(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            main(["json"])

        assert excinfo.value.code == 2
        out, err = capsys.readouterr()
        assert out == ""
        assert err.startswith(
            f"usage: {prog_name} json [-h] names [names ...]\n"
            + f"{prog_name} json: error: the following arguments are required: names\n"
        )

    def test_json_invalid_name(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            main(["json", "instance-id", "invalid-name!"])

        assert excinfo.value.code == 2
        out, err = capsys.readouterr()
        assert out == ""
        assert err.startswith(
            f"usage: {prog_name} json [-h] names [names ...]\n"
            + f"{prog_name} json: error: argument names: Invalid metadata name: invalid-name!. Must be one of: account_id, ami_id, "
        )

    def test_json_valid_names(self, capsys):
        with mock.patch("ec2_metadata.cli.ec2_metadata") as mock_metadata:
            mock_metadata.instance_id = "i-1234567890abcdef0"
            mock_metadata.availability_zone = "us-east-1a"

            main(["json", "instance-id", "availability-zone"])

        out, err = capsys.readouterr()
        # fmt: off
        assert out == (
            "{\n"
            '  "instance-id": "i-1234567890abcdef0",\n'
            '  "availability-zone": "us-east-1a"\n'
            "}\n"
        )
        # fmt: on
        assert err == ""
