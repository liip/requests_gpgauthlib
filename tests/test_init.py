import pytest

from gpgauth import GPGAuth


def test_stage0():
    ga = GPGAuth()
    assert ga.requests is True
