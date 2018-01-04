import pytest

from gpgauth import GPGAuth


def test_init_void():
    # No Arguments, it fails
    with pytest.raises(TypeError):
        GPGAuth()
