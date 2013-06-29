pacman
======

### introduction

a python web proxy server to nail cross-domain application development.
one of the most essential utilities for the cross-domain application toolbelt
since resurrections n' shit.


-----


### what is it used for?

it serves a local server, which proxies requests from one domain to another.

this would allow a developer to work locally, and be able to route all requests
to `somedomain.com` to a server of their choice, eliminating the need to modify
the `/etc/hosts` file, or configuring local domain name servers.


### how does it work?
run the proxy server and navigate to the url `http://localhost:3128/pacman.pac`
file will best illustrate how the javascript-like syntax will work:
    `pacman`


### use cases?
- useful for developing and testing domains and sub-domains on a local machine.
- debug cross domain cookies
- debug iframe message passing


-----


### usage

    pacman [options] ...

    OPTIONS:
      --host=HOST           host name to bind the proxy server to.
      --port=PORT           port to bind the proxy server to.
      --max-threads         maximum number of active threads.
      --log-level           logging output level.defaulst
      --proxy-config        proxy configuration yaml file.


-----


### links

* [docs](http://gregorynicholas.github.io/pacman)
* [source](http://github.com/gregorynicholas/pacman)
* [package](http://packages.python.org/pacman)
