pacman
======

a python web proxy server to nail cross-domain application development.
one of the most essential utilities for the cross-domain application toolbelt
since resurrections n' shit.


<br>
**build-status:**

`master  ` [![travis-ci build-status: master](https://secure.travis-ci.org/gregorynicholas/pacman.svg?branch=master)](https://travis-ci.org/gregorynicholas/pacman)
<br>
`develop ` [![travis-ci build-status: develop](https://secure.travis-ci.org/gregorynicholas/pacman.svg?branch=develop)](https://travis-ci.org/gregorynicholas/pacman)


**links:**

- [homepage](http://gregorynicholas.github.io/pacman)
- [source](http://github.com/gregorynicholas/pacman)
- [python-package](http://packages.python.org/pacman)
- [changelog](https://github.com/gregorynicholas/pacman/blob/master/CHANGES.md)
- [github-issues](http://github.com/gregorynicholas/pacman/issues)
- [travis-ci](http://travis-ci.org/gregorynicholas/pacman)
- [semantic versioning specification](http://semver.org)


<br>
-----
<br>


### introduction


-----


### what is it used for?

it serves a local server, which proxies requests from one domain to another.

this would allow a developer to work locally, and be able to route all requests
to `somedomain.com` to a server of their choice, eliminating the need to modify
the `/etc/hosts` file, or configuring local domain name servers.


### how does it work?
run the proxy server and navigate to the url `http://localhost:3128/pacman.pac`
file will best illustrate how the javascript-like syntax will work:

    $ pacman
    $ open 'http://localhost:3128/pacman.pac'


### use cases?
- useful for developing and testing domains and sub-domains on a local machine.
- debug cross domain cookies
- debug iframe message passing


<br>
-----
<br>


### installation

install keybump with pip

    $ pip install keybump==3.0.1


<br>
-----
<br>


### usage

    pacman [options] ...

    OPTIONS:
      --host=HOST           host name to bind the proxy server to.
      --port=PORT           port to bind the proxy server to.
      --max-threads         maximum number of active threads.
      --log-level           logging output level.defaulst
      --proxy-config        proxy configuration yaml file.
