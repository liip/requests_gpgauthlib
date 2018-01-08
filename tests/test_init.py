import pytest

from requests_gpgauthlib.gpgauth_session import GPGAuthSession


def test_init_void():
    # No Arguments, it fails
    with pytest.raises(TypeError):
        GPGAuthSession()
