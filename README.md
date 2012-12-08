# proxy web server written in python.

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
