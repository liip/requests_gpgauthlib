requests_gpgauthlib - A requests GPGAuth authentication library
===============================================================

[![Build Status](https://travis-ci.org/liip/requests_gpgauthlib.svg?branch=master)](https://travis-ci.org/liip/requests_gpgauthlib)

Example usage
-------------

```
import requests

from requests_gpgauthlib import GPGAuthSession
from requests_gpgauthlib.utils import create_gpg, get_workdir, import_user_private_key_from_file

SERVER_URL = 'https://demo.passbolt.com'
SERVER_FINGERPRINT = '6810A8F7728F4A7CE936F93BA27743FA0C9E83E0'

gpg = create_gpg(get_workdir())

import_user_private_key_from_file(gpg, '~/Downloads/passbolt_private.asc')

ga = GPGAuthSession(
  gpg=gpg,
  auth_url=SERVER_URL + '/auth/',
  server_fingerprint=SERVER_FINGERPRINT,
)
ga.authenticate()
all_resources = ga.get(SERVER_URL + '/resources.json', params={'contain[secret]': 1}).json()['body']
print(all_resources)
```
