"""
Shared pytest fixtures.

Tests import the audit library / scripts as `from lib.aws_common import …`
and `from audits import nsf1`. Both work because `aws/` is added to
sys.path here.
"""

import os
import sys
from pathlib import Path

import pytest

# Add aws/ to sys.path so `lib.aws_common` and `audits.nsfN` resolve when
# pytest is run from anywhere (repo root, aws/, or aws/tests/).
AWS_ROOT = Path(__file__).resolve().parent.parent
if str(AWS_ROOT) not in sys.path:
    sys.path.insert(0, str(AWS_ROOT))


@pytest.fixture(autouse=True)
def _reset_permission_failures():
    """Each test starts with a clean permission-failure counter."""
    from lib.aws_common import reset_permission_failures
    reset_permission_failures()
    yield
    reset_permission_failures()


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch):
    """Strip credential / role env vars so tests don't leak between machines."""
    for var in (
        'AWS_ACCESS_KEY_ID',
        'AWS_SECRET_ACCESS_KEY',
        'AWS_SESSION_TOKEN',
        'AWS_PROFILE',
        'AWS_EXTERNAL_ID',
        'NSF_AUDIT_ROLE',
        'WORKSPACE',
    ):
        monkeypatch.delenv(var, raising=False)
    yield
