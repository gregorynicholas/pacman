#!/usr/bin/env python
"""
  pacman
  ~~~~~~

  pacfile proxy web server written in python. useful for developing and testing
  cross-domain applications. one step install, easily configured via yaml.


  :copyright: (c) 2013 by gregorynicholas.
  :license: BSD, see LICENSE for more details.
"""

import sys
try:
  import yaml
except ImportError:
  print "please install yaml dependency.."
import logging
import logging.handlers
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from optparse import OptionParser
from SocketServer import ThreadingMixIn
from threading import Event
from threading import activeCount
import select
import socket
import urlparse
from types import FrameType, CodeType
from signal import signal, SIGINT


usage = """\
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


PROXIES_PATH = "pacman.yaml"
# pylint #E501 disable
LOG_FMT = "[%(asctime)-12s] %(levelname)-8s {%(name)s \
%(threadName)s} %(message)s "


def get_proxy_config(path):
  """
  load server config definitions from a yaml file.
  """
  f = open(path, 'r')
  result = yaml.safe_load(f)
  f.close()
  return result


class ProxyPAC(object):
  """
  """
  def __init__(self):
    """
    """

  def write(self):
    result = """
    function FindProxyForURL(url, host) {
    """
    for host in self.proxy_hosts:
      result += """
      if (shExpMatch(url,"*{name}*"))
        return "PROXY {forward_host}:{forward_port}";
      """.format(**host)
    result += """
      return "DIRECT";
    }"""
    self.wfile.write(result)


class ProxyHandler(BaseHTTPRequestHandler):
  """
  proxy server request handler.
  """

  def __init__(self, *args, **kwargs):
    BaseHTTPRequestHandler.__init__(self, *args, **kwargs)
    self.protocol = "HTTP/1.0"
    self._proxy_config = None
    self._proxy_hosts = None
    self._pacfile_config = None

  @property
  def proxy_config(self):
    if self._proxy_config is None:
      self._proxy_config = get_proxy_config(PROXIES_PATH)
    return self._proxy_config

  @property
  def proxies(self):
    if self._proxies is None:
      self._proxies = self.proxy_config.get('proxies')
    return self._proxies

  @property
  def pacfile_config(self):
    if self._pacfile_config is None:
      self._pacfile_config = self.proxy_config.get('pacfile')
    return self._pacfile_config

  def handle(self):
    (ip, port) = self.client_address
    self.server.logger.info("Request from '%s'", ip)
    if hasattr(self, 'allowed_clients') and ip not in self.allowed_clients:
      self.raw_requestline = self.rfile.readline()
      if self.parse_request():
        self.send_error(403)
    else:
      return BaseHTTPRequestHandler.handle(self)

  def write_proxy_pac(self):
    """
    renders the proxy pacfile from the definitions in the proxy configuration.
    """
    result = """
    function FindProxyForURL(url, host) {
    """
    for host in self.proxies:
      result += """
      if (shExpMatch(url,"*{name}*"))
        return "PROXY {forward_host}:{forward_port}";
      """.format(**host)
    result += """
      return "DIRECT";
    }"""
    self.wfile.write(result)

  def do_GET(self):
    (scm, netloc, path, params, query, fragment) = urlparse.urlparse(
      self.path, 'http')
    if self.path == self.pacfile_config.get('path'):
      return self.write_proxy_pac()
    if scm != 'http' or fragment or not netloc:
      self.send_error(400, "bad url %s" % self.path)
      return
    server_host = self.proxy_hosts.get(netloc)
    message = ''
    if "Content-Length" in self.headers:
      content_length = self.headers["Content-Length"]
      print "message length: ", content_length
      if content_length > 0:
        message = self.rfile.read(int(content_length))
        print "message: ", message

    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
      if self._connect_to(server_host.name, server_host.port, soc):
        self.log_request()
        soc.send("%s %s %s\r\n" % (
          self.command, urlparse.urlunparse(('', '', path, params, query, '')),
          self.request_version))
        self.headers['Connection'] = 'close'
        del self.headers['Proxy-Connection']
        # print 'URL: %s request' % self.path
        for key_val in self.headers.items():
          soc.send("%s: %s\r\n" % key_val)
          print '%s: %s\n' % key_val
        soc.send("\r\n%s\r\n" % message)
        self._read_write(soc)
    finally:
      soc.close()
      self.connection.close()

  def _connect_to(self, host, port, soc):
    self.server.logger.debug("connect to %s:%d", host, port)
    try:
      soc.connect(port)
    except socket.error, arg:
      try:
        msg = arg[1]
      except:
        msg = arg
      self.send_error(404, msg)
      return 0
    return 1

  def _read_write(self, soc, max_idling=20, local=False):
    """
      :param soc:
      :param max_idling:
      :param local:
    """
    iw = [self.connection, soc]
    ow = []
    count = 0
    while 1:
      count += 1
      (ins, _, exs) = select.select(iw, ow, iw, 1)
      if exs:
        break
      if ins:
        for i in ins:
          if i is soc:
            out = self.connection
          else:
            out = soc
          data = i.recv(8192)
          if data:
            out.send(data)
            count = 0
      if count == max_idling:
        break

  do_PUT = do_GET
  do_HEAD = do_GET
  do_POST = do_GET
  do_DELETE = do_GET
  do_OPTIONS = do_GET

  def log_message(self, format, *args):
    self.server.logger.info("%s %s", self.address_string(), format % args)

  def log_error(self, format, *args):
    self.server.logger.error("%s %s", self.address_string(), format % args)


class ProxyHTTPServer(ThreadingMixIn, HTTPServer):
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
  `ProxyHTTPServer` context object. runs an instance of a `ProxyHTTPServer`,
  manages active threading, & binds to command line exit sigals.
  """

  def __init__(self, host, port, max_threads):
    """
      :param host: string hostname to bind the proxy server to.
      :param port: port integer to bind the proxy server to.
      :param max_threads: maximum number of active threads.
    """
    self.max_threads = max_threads
    self.active_thread_count = 0
    self.host = host
    self.port = port
    self.handler_class = ProxyHandler
    self.set_exit_handler()

  @property
  def hostname(self):
    return (self.host, self.port)

  def run(self):
    """
    runs the `ProxyHTTPServer`.
    """
    self.server = ProxyHTTPServer(self.hostname, self.handler_class)
    self.sock = self.server.socket.getsockname()
    self.server.logger.info(
      "serving http on: %s port: %s", self.sock[0], self.sock[1])
    self.active_thread_count = 0
    while not self.exit_event.isSet():
      try:
        self.server.handle_request()
        self.active_thread_count = activeCount()
        self.server.logger.info(
          "active thread count: %s", self.active_thread_count)
        if self.active_thread_count >= self.max_threads:
          self.on_max_threads()
      except select.error, e:
        print 'select.error', e
        self, self.on_exit_event(e[0], e[1])

    self.server.logger.info("proxy server shutdown..")

  def on_max_threads(self):
    self.server.logger.warn(
      "maximum active threads reached. resetting count..")
    # todo: more action to take here?
    self.active_thread_count = 0

  def set_exit_handler(self):
    """
    binds a signal to listen for `KeyboardInterrupt` events.
    """
    self.exit_event = Event()
    signal(SIGINT, self.exit_handler)

  def exit_handler(self, signo, frame):
    """
    event handler method for `KeyboardInterrupt` events.

      :param signo:
      :param frame:
    """
    while frame and isinstance(frame, FrameType):
      if frame.f_code and isinstance(frame.f_code, CodeType):
        # this goes through the stack to find the instance of the ProxyContext
        # to respond to this event..
        if "self" in frame.f_code.co_varnames:
          _self = frame.f_locals["self"]
          if isinstance(_self, ProxyContext):
            _self.exit_event.set()
            exit(0)
      frame = frame.f_back

  def on_exit_event(self, code, msg):
    """
      :param code:
      :param msg:
    """
    print "on_exit_event", code, msg
    if code != 4 and not self.exit_event.isSet():
      self.server.logger.critical("error: code: %d, %s", code, msg)
      self.fail(msg)


def fail(message, *args):
  print >> sys.stderr, 'error:', message.format(*args),
  exit(1)


def usage():
  print >> sys.stdout, usage,


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
  help="proxy configuration yaml file.")

parser.add_option(
  "--log-level", dest="log_level", metavar="LEVEL",
  help="logging output level.")


def main():
  (options, args) = parser.parse_args()
  ProxyContext(
    options.host, options.port, options.max_threads).run()
  sys.exit(0)


if __name__ == '__main__':
  main()
