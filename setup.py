#!/usr/bin/env python
"""
  pacman
  ------

  pacfile proxy web server written in python. useful for developing and testing
  cross-domain applications. one step install, easily configured via yaml.

"""
from setuptools import setup


with open("requirements.txt", "r") as f:
  requires = f.readlines()


setup(
  name='pacman',
  version='0.0.1',
  url='http://github.com/gregorynicholas/pacman',
  license='MIT',
  author='gregorynicholas',
  author_email='gn@gregorynicholas.com',
  description=__doc__,
  long_description=__doc__,
  py_modules=['pacman'],
  include_package_data=True,
  data_files=['pacman.yaml'],
  zip_safe=False,
  platforms='any',
  install_requires=[
    'pyyaml==3.10',
  ],
  tests_require=[
    'nose==1.2.1',
    'nose-cov==1.6',
  ],
  test_suite='nose.collector',
  classifiers=[
    'Development Status :: 4 - Beta',
    'Environment :: Web Environment',
    'Intended Audience :: Developers',
    'License :: OSI Approved :: MIT License',
    'Operating System :: OS Independent',
    'Programming Language :: Python',
    'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
    'Topic :: Software Development :: Libraries :: Python Modules'
  ]
)
