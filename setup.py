#!/usr/bin/env python
"""
python-proxy-server
-----------------------

## what is it used for?
it serves a local server, which proxies requests from one domain to another.

this would allow a developer to work locally, and be able to route all requests
to `somedomain.com` to a server of their choice, eliminating the need to modify
the `/etc/hosts` file, or configuring local domain name servers.


## how does it work?
run the proxy server and navigate to the url `http://localhost:3128/proxyserver.pac`
file will best illustrate how the javascript-like syntax will work:
    `python server.py`


## use cases?
- useful for developing and testing domains and sub-domains on a local machine.
- debug cross domain cookies
- debug iframe message passing


Links
`````

* `documentation <http://packages.python.org/python-proxy-server>`_
* `development version
  <http://github.com/gregorynicholas/python-proxy-server/zipball/master#egg=python-proxy-server-dev>`_

"""
from setuptools import setup

setup(
  name='python-proxy-server',
  version='1.0.0',
  url='http://github.com/gregorynicholas/python-proxy-server',
  license='MIT',
  author='gregorynicholas',
  description='Proxy web server written in python.',
  long_description=__doc__,
  py_modules=['server', 'server_tests'],
  include_package_data=True,
  data_files=['proxies.yaml'],
  zip_safe=False,
  platforms='any',
  install_requires=[
    'pyyaml',
  ],
  tests_require=[
    'nose',
  ],
  dependency_links = [
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
