#!/usr/bin/env python
"""
  pacman
  ~~~~~~

  pacfile proxy web server written in python. useful for developing and testing
  cross-domain applications. one step install, easily configured via yaml.


  :copyright: (c) 2015 by gregorynicholas.
  :license: BSD, see LICENSE for more details.
"""
import sys
import logging
import logging.handlers
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from optparse import OptionParser
from SocketServer import ThreadingMixIn
from threading import Event
from threading import activeCount
import select
import socket
from urlparse import urlparse, urlunparse
from types import FrameType, CodeType
from signal import signal, SIGINT

try:
  import yaml
except ImportError:
  print "python-yaml dependency not installed.."


USAGE = """\
pacman

pacman [OPTIONS] ...

description: a python web proxy server to nail cross-domain application
development. one of the most essential utilities for the cross-domain
application toolbelt since resurrections n' shit.

OPTIONS:
  --host=HOST           host name to bind the proxy server to.
  --port=PORT           port to bind the proxy server to.
  --max-threads         maximum number of active threads.
  --log-level           logging output level.defaulst
  --proxy-config        proxy configuration yaml file.
"""


CONFIG_PATH = "pacman.yaml"
# pylint #E501 disable
LOG_FMT = "[%(asctime)-12s] %(levelname)-8s {%(name)s \
%(threadName)s} %(message)s "


def load_proxy_config(path):
  """
  load server config definitions from a yaml file.
  """
  with open(path, 'r') as f:
    result = yaml.safe_load(f)
    f.close()
  return result


class ProxyHandler(BaseHTTPRequestHandler):
  """
  proxy server request handler.
  """

  def __init__(self, *args, **kwargs):
    BaseHTTPRequestHandler.__init__(self, *args, **kwargs)
    self.protocol = "HTTP/1.0"
    self.protocol_scheme = 'http'
    self._proxy_config = None
    self._proxy_rules = None
    self._pacfile_config = None

  @property
  def proxy_config(self):
    if not hasattr(self, '_proxy_config') or self._proxy_config is None:
      self._proxy_config = load_proxy_config(CONFIG_PATH)
    return self._proxy_config

  @property
  def proxy_rules(self):
    if not hasattr(self, '_proxy_rules') or self._proxy_rules is None:
      self._proxy_rules = self.proxy_config.get('proxy_rules')
    return self._proxy_rules

  @property
  def pacfile_config(self):
    if not hasattr(self, '_pacfile_config') or self._pacfile_config is None:
      self._pacfile_config = self.proxy_config.get('pacfile')
    return self._pacfile_config


  def handle(self):
    """
    handles all requests
    """
    (ip, port) = self.client_address
    self.server.logger.info("handling request from ip: {}".format(ip))

    if hasattr(self, 'allowed_clients') and ip not in self.allowed_clients:
      self.raw_requestline = self.rfile.readline()
      if self.parse_request():
        self.send_error(403)

    else:
      return BaseHTTPRequestHandler.handle(self)


  def render_pacfile(self):
    """
    renders the proxy pacfile from the definitions in the proxy configuration.
    """
    proxy_rule = """
      if (shExpMatch(url, "*{name}*"))
        return "PROXY {forward_host}:{forward_port}";
    """
    proxy_rules = [proxy_rule.format(**host) for host in self.proxy_rules]

    body = """
    function FindProxyForURL(url, host) {
      {}
      return "DIRECT";
    }
    """.format(''.join(proxy_rules))

    self.wfile.write(body)


  def urlparse(self, scheme, host, path, params, query, fragment):
    """
    parses the result of `urlparse()` to a dict.
    """
    return {
      'scheme': scheme,
      'host': host,
      'path': path,
      'params': params,
      'query': query,
      'fragment': fragment}


  def urlunparse(self, request):
    urlunparse(
      ('', '', request['path'], request['params'], request['query'], ''))


  def do_GET(self):
    """
    handles a GET request
    """
    request = self.urlparse(*urlparse(self.path, self.protocol_scheme))

    if self.is_pacfile_path():
      return self.render_pacfile()

    # TODO: for now, don't know how to handle fragments..
    if request['fragment']:
      self.send_error(400, "unsupported url: {}".format(self.path))
      return

    # TODO: handling other request types unimplemented..
    if request['scheme'] != 'http':
      self.send_error(400, "unsupported url: {}".format(self.path))
      return

    if not request['host']:
      self.send_error(400, "bad url: {}".format(self.path))
      return

    self.send_proxy_request(request, self.proxy_rules[request['host']])


  def is_pacfile_path(self):
    """
    returns a boolean if the current request path is the pacfile.
    """
    return self.path.lower() == self.pacfile_config['path'].lower()


  def send_proxy_request(self, request, forward_proxy):
    """
    fowards a proxy request.
    """
    body = ''
    length = self.headers.get("Content-Length", 0)
    if length > 0:
      body = self.rfile.read(int(length))
      self.server.logger.debug(
        "body (content-length {}): ".format(length, body))

    proxy_s = self.create_proxy_socket()
    try:
      if self.proxy_socket_connect(proxy_s, forward_proxy.port):
        self.log_request()

        proxy_s.send("{} {} {}\r\n".format(
          self.command, self.urlunparse(request), self.protocol))

        self.headers['Connection'] = 'close'
        del self.headers['Proxy-Connection']
        self.server.logger.debug('URL: {} request'.format(self.path))

        # send headers
        [proxy_s.send("{}: {}\r\n".format(*kv)) for kv in self.headers.items()]

        # send body
        proxy_s.send("\r\n{}\r\n".format(body))
        self.socket_rw(proxy_s)
    except Exception, e:
      self.server.logger.exception(e)

    finally:
      proxy_s.close()
      self.connection.close()


  def create_proxy_socket(self):
    return socket.socket(socket.AF_INET, socket.SOCK_STREAM)


  def proxy_socket_connect(self, proxy_s, port):
    self.server.logger.debug("connect to {}:{}".format(proxy_s, port))
    try:
      proxy_s.connect(port)

    except socket.error, arg:
      self.server.logger.exception(e)
      try:
        msg = arg[1]
      except:
        msg = arg
      self.send_error(404, msg)
      return 0

    return 1


  def socket_rw(self, proxy_s, max_idle_ticks=20):
    """
      :param proxy_s:
      :param max_idle_ticks:
      :param local:
    """
    iw = [self.connection, proxy_s]
    ow = []
    timer = 0

    while 1:
      timer += 1
      (ins, _, exs) = select.select(iw, ow, iw, 1)
      if exs:
        break

      if ins:
        for i in ins:
          if i is proxy_s:
            out = self.connection
          else:
            out = proxy_s

          data = i.recv(8192)
          if data:
            out.send(data)
            timer = 0

      if timer == max_idle_ticks:
        break


  do_PUT = do_GET
  do_HEAD = do_GET
  do_POST = do_GET
  do_DELETE = do_GET
  do_OPTIONS = do_GET


class ProxyHTTPServer(ThreadingMixIn, HTTPServer):
  """
  """

  def __init__(self, server_address, request_handler_class):
    HTTPServer.__init__(self, server_address, request_handler_class)
    self.logger = self.create_logger()

  def create_logger(self):
    rv = logging.getLogger(self.__class__.__name__.split('.')[-1])
    rv.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    formatter = logging.Formatter(LOG_FMT)
    handler.setFormatter(formatter)
    rv.addHandler(handler)
    return rv


class ProxyContext(object):
  """
  `ProxyHTTPServer` context object. runs an instance of a `ProxyHTTPServer`.
  manages threading & binds to command line exit sigals.
  """

  def __init__(self, host, port, max_threads):
    """
      :param host: string hostname to bind the proxy server to.
      :param port: port integer to bind the proxy server to.
      :param max_threads: maximum number of active threads.
    """
    self.host = host
    self.port = port
    self.max_threads = max_threads
    self.active_thread_count = 0
    self.handler_class = ProxyHandler
    self.set_sigint_handler()


  @property
  def hostname(self):
    return (self.host, self.port)


  def run(self):
    """
    runs the `ProxyHTTPServer`
    """
    self.server = ProxyHTTPServer(self.hostname, self.handler_class)

    host, port = self.server.socket.getsockname()[:2]
    self.server.logger.info(
      "serving http on host: {} port: {}".format(host, port))

    self.active_thread_count = 0

    while not self.sigint_event.isSet():
      try:
        self.server.handle_request()
        self.active_thread_count = activeCount()
        self.server.logger.info(
          "active thread count: {}".format(self.active_thread_count))

        if self.active_thread_count >= self.max_threads:
          self.on_max_threads()

      except select.error, err:
        self.server.logger.debug("select.error: {}".format(e))
        self.on_sigint(*err)

    self.server.logger.info("proxy server shutdown..")


  def on_max_threads(self):
    self.server.logger.warn(
      "maximum active threads reached. resetting count..")
    # todo: more action to take here?
    self.active_thread_count = 0


  def set_sigint_handler(self):
    """
    binds a signal to listen for `KeyboardInterrupt` events.
    """
    self.sigint_event = Event()
    signal(SIGINT, self.sigint_handler)


  def sigint_handler(self, sigint, frame):
    """
    event handler method for `KeyboardInterrupt` events.

      :param sigint:
      :param frame:
    """
    self.server.logger.debug(
      "SIGINT event received: {}, {}".format(sigint, frame))

    while frame and isinstance(frame, FrameType):
      if frame.f_code and isinstance(frame.f_code, CodeType):
        # this goes through the stack to find the instance of the ProxyContext
        # to respond to this event..
        if "self" in frame.f_code.co_varnames:
          _self = frame.f_locals["self"]
          if isinstance(_self, ProxyContext):
            _self.sigint_event.set()
            exit(0)
      frame = frame.f_back


  def on_sigint(self, code, msg, *args):
    """
      :param code:
      :param msg:
    """
    self.server.logger.debug("on_sigint, code: {} msg: {}".format(code, msg))

    if code != 4 and not self.sigint_event.isSet():
      self.server.logger.critical("on_sigint error, code: {}, {}".format(code, msg))
      self.fail(msg)


def fail(message, *args):
  print >> sys.stderr, 'error:', message.format(*args),
  exit(1)


def usage():
  print >> sys.stdout, USAGE,


parser = OptionParser(
  description="""description: a python web proxy server to nail cross-domain
application development. one of the most essential utilities for the
cross-domain application toolbelt since resurrections n' shit.""",
  prog="pacman",
  usage="%prog [OPTIONS]")

parser.add_option(
  "--host", dest="host", default="localhost",
  help="host name to bind the proxy server to.")

parser.add_option(
  "--port", dest="port", default=3128,
  help="port to bind the proxy server to.")

parser.add_option(
  "--max-threads", dest="max_threads", default=1000,
  help="maximum number of active threads.")

parser.add_option(
  "--proxy-config", dest="proxy_config", default="pacman.yaml",
  help="proxy pacfile configuration yaml file.")

parser.add_option(
  "--log-level", dest="log_level", metavar="LEVEL",
  help="logging output level.")


def main():
  (options, args) = parser.parse_args()

  ProxyContext(
    options.host, options.port, options.max_threads).run()
  exit(0)


if __name__ == '__main__':
  main()
