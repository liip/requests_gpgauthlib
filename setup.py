#!/usr/bin/env python

from setuptools import find_packages, setup

setup(name='requests_gpgauthlib',
      version='0.0.4',
      description='requests_gpgauthlib - A requests GPGAuth authentication library',
      author='Didier \'OdyX\' Raboud',
      author_email='odyx@liip.ch',
      url='https://github.com/liip/requests_gpgauthlib',
      install_requires=[
          'python-gnupg',
          'requests'
      ],
      tests_require=['pytest'],
      packages=find_packages()
      )
