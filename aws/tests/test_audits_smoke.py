"""
Smoke tests for every audit script.

Confirms that:
  - The module imports cleanly (no stale references to removed helpers
    like `handle_upload` / `gdrive_upload`).
  - The argument parser builds (catches the `%` argparse bug we hit earlier
    in nsf5 / nsf8 / nsf9 epilogs).
  - The expected common arguments are present.
  - The module-level `logger` is bound under `nsf_audit.nsfN`.
"""

import argparse
import importlib
from pathlib import Path

import pytest

AUDITS_DIR = Path(__file__).resolve().parent.parent / 'audits'
SCRIPTS = sorted(
    p.stem for p in AUDITS_DIR.glob('nsf*.py')
)


@pytest.mark.parametrize('name', SCRIPTS)
def test_import(name):
    """Every audit module imports without errors."""
    importlib.import_module(f'audits.{name}')


@pytest.mark.parametrize('name', SCRIPTS)
def test_main_function_exists(name):
    mod = importlib.import_module(f'audits.{name}')
    assert callable(getattr(mod, 'main', None)), \
        f"audits.{name} is missing a callable main()"


@pytest.mark.parametrize('name', SCRIPTS)
def test_run_audit_exists(name):
    mod = importlib.import_module(f'audits.{name}')
    assert callable(getattr(mod, 'run_audit', None)), \
        f"audits.{name} is missing a callable run_audit()"


@pytest.mark.parametrize('name', SCRIPTS)
def test_logger_namespace(name):
    """Each script must bind `logger` under the `nsf_audit.<name>` namespace."""
    mod = importlib.import_module(f'audits.{name}')
    assert hasattr(mod, 'logger'), f"audits.{name} has no module-level logger"
    assert mod.logger.name == f'nsf_audit.{name}', (
        f"audits.{name}.logger is {mod.logger.name!r}, expected nsf_audit.{name}"
    )


@pytest.mark.parametrize('name', SCRIPTS)
def test_argparse_help_does_not_raise(name, capsys):
    """The argparse epilog must format correctly (catches `%` quoting bugs)."""
    mod = importlib.import_module(f'audits.{name}')
    parser_holder: dict[str, argparse.ArgumentParser] = {}

    # Monkey-patch parse_args to capture the parser before it consumes argv.
    real_make = argparse.ArgumentParser.parse_args

    def _capture(self, *a, **kw):
        parser_holder['p'] = self
        # Force --help: SystemExit catches it.
        raise SystemExit(0)

    argparse.ArgumentParser.parse_args = _capture
    try:
        with pytest.raises(SystemExit):
            mod.main()
    finally:
        argparse.ArgumentParser.parse_args = real_make

    parser = parser_holder['p']
    # format_help() exercises the same code path that previously broke on
    # unescaped `%` characters in epilogs.
    help_text = parser.format_help()
    assert help_text  # non-empty
    assert '--output-dir' in help_text
    assert '--format' in help_text
    assert '--external-id' in help_text
    assert '--verbose' in help_text or '-v' in help_text


@pytest.mark.parametrize('name', SCRIPTS)
def test_common_arguments_present(name):
    """Every script exposes the common CLI surface."""
    mod = importlib.import_module(f'audits.{name}')
    parser_holder: dict[str, argparse.ArgumentParser] = {}
    real_make = argparse.ArgumentParser.parse_args

    def _capture(self, *a, **kw):
        parser_holder['p'] = self
        raise SystemExit(0)

    argparse.ArgumentParser.parse_args = _capture
    try:
        with pytest.raises(SystemExit):
            mod.main()
    finally:
        argparse.ArgumentParser.parse_args = real_make

    parser = parser_holder['p']
    dests = {a.dest for a in parser._actions}  # noqa: SLF001
    for expected in (
        'accounts', 'role', 'profile', 'output_dir', 'format',
        'external_id', 'verbose', 'quiet', 'log_file',
    ):
        assert expected in dests, (
            f"audits.{name} parser is missing --{expected.replace('_', '-')}"
        )


def test_all_thirteen_scripts_present():
    """Regression guard — we should always have nsf1..nsf13."""
    expected = {f'nsf{i}' for i in range(1, 14)}
    assert set(SCRIPTS) == expected, f"Missing scripts: {expected - set(SCRIPTS)}"
