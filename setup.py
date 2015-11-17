#!/usr/bin/env python
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(name='secondguard-api-wrapper',
      version='1.1.0',
      description='SecondGuard API Wrapper',
      author='Michael Flaxman',
      author_email='mflaxman+secondguardwrapper@gmail.com',
      url='https://github.com/secondguard/secondguard-python/',
      install_requires=[
          'requests==2.8.1',
          ],
      packages=['secondguard'],
      include_package_data=True,
      package_data={"": ["LICENSE"]},
      )
