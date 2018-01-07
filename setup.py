#!/usr/bin/env python

from setuptools import setup

gnupg_hash = 'bb2eb8134660930f2c6a1528a334fdd5e1214c4a'
gnupg_vers = '2.3.1-10-gbb2eb81-dirty'

setup(name='python-gpgauth-cli',
      version='0.2018010400',
      description='gpgauth-cli - A GPGAuth Client library',
      author='Didier \'OdyX\' Raboud',
      author_email='odyx@liip.ch',
      url='https://github.com/liip/python-gpgauth-cli',
      install_requires=[
          'gnupg==%s' % gnupg_vers,
          'requests'
      ],
      dependency_links=[
          (
              'git+https://github.com/OdyX/python-gnupg.git@%s#egg=gnupg'
              % gnupg_hash
          ),
      ],
      tests_require=['pytest'],
      )
