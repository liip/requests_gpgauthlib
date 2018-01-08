#!/usr/bin/env python3

import requests

from requests_gpgauthlib.gpgauth_session import GPGAuthSession

SERVER_URL = 'https://demo.passbolt.com/'

# Instantiate the GPGAuth object
ga = GPGAuthSession(
    auth_url=SERVER_URL + '/auth/',
    server_fingerprint='6810A8F7728F4A7CE936F93BA27743FA0C9E83E0',
)

# Any non-authenticated request will be authenticated first
resources_req = ga.get(SERVER_URL + '/resources.json')
all_resources = resources_req.json()['body']
first_resource = all_resources[0]

name = first_resource['Resource']['name']
secret = ga.gpg.decrypt(first_resource['Secret'][0]['data'], always_trust=True)

print("My secret %s: %s" % (name, secret))
