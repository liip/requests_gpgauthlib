#!/usr/bin/env python

from setuptools import setup

setup(name='python-gpgauth-cli',
      version='0.2018010400',
      description='gpgauth-cli - A GPGAuth Client library',
      author='Didier \'OdyX\' Raboud',
      author_email='odyx@liip.ch',
      url='https://github.com/liip/python-gpgauth-cli',
      install_requires=['gnupg', 'requests'],
      tests_require=['pytest'],
      )
