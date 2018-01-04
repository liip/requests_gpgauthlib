#!/usr/bin/env python3

from gpgauth import GPGAuth

# Instantiate the GPGAuth object
ga = GPGAuth(
    server_url='https://dermo.passbolt.com',
    server_fingerprint='6810A8F7728F4A7CE936F93BA27743FA0C9E83E0',
    user_private_key_file='/tmp/passbolt_private.asc')

# You can run through each step individually:
ga.stage0()
# or ga.verify_server_identity()

ga.stage1()
# or ga.login()

ga.stage2()
# or ga.authenticate_with_token

# Then some objects are available for you:
# ga.gpg has your GnuPG key in an instance-specific GPG homedir
# ga.requests is a python-requests object that has the session cookie. In other words, it's authenticated!


# Bonus: if you access ga.requests directly, it will attempt a login at first use.

# On a passbolt server, try:

all_resources = ga.requests.get(ga.server_url + '/resources.json').json()['body']
first_resource = all_resources[0]

name = first_resource['Resource']['name']
secret = ga.gpg.decrypt(first_resource['Secret'][0]['data'], always_trust=True)

print("My secret %s: %s" % (name, secret))
