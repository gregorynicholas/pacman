#!/usr/bin/env python
'''Test proxy web server written in python. Useful for developing for and
testing domains and sub domains.'''

import sys
import yaml
import getopt
import logging
import logging.handlers
import threading
import BaseHTTPServer, SocketServer
import select, socket, urlparse
from types import FrameType, CodeType
from signal import signal, SIGINT

SERVERS_PATH = 'servers.yaml'

def get_servers(path):
  f = open(path, 'r')
  result = yaml.safe_load(f)
  f.close()
  return result

class ProxyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
  __base = BaseHTTPServer.BaseHTTPRequestHandler
  __base_handle = __base.handle

  def __init__(self, *args, **kw):
    BaseHTTPServer.BaseHTTPRequestHandler.__init__(self, *args, **kw)
    self.servers = get_servers(SERVERS_PATH)
    self.server_hosts = self.servers.get('hosts')
    self.proxy_config = self.servers.get('proxy')

  def handle(self):
    (ip, port) = self.client_address
    self.server.logger.info("Request from '%s'", ip)
    if hasattr(self, 'allowed_clients') and ip not in self.allowed_clients:
      self.raw_requestline = self.rfile.readline()
      if self.parse_request(): self.send_error(403)
    else:
      self.__base_handle()

  def _connect_to(self, host, port, soc):
    self.server.logger("connect to %s:%d", host, port)
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

  def write_proxy_pac(self):
    # send requests to google apps domain to direct
    self.wfile.write('''
    function FindProxyForURL(url, host) {
      if (shExpMatch(url,"*mail.%s*"))
        return "DIRECT";
      if (shExpMatch(host,"*mail.%s*"))
        return "DIRECT";
      if (shExpMatch(url,"*%s*"))
        return "PROXY %s:%d";
      return "DIRECT";
    }''' % (
      self.server_hosts.get('host'), self.server_hosts.get('host'),
      self.proxy_config.get('host'), self.proxy_config.get('port'),
    ))
    return

  def do_GET(self):
    (scm, netloc, path, params, query, fragment) = urlparse.urlparse(
      self.path, 'http')

    if self.path == self.proxy_config.get('path'):
      return self.write_proxy_pac()

    if scm != 'http' or fragment or not netloc:
      self.send_error(400, "bad url %s" % self.path)
      return

    server_host = self.server_hosts.get(netloc)
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
        soc.send("%s %s %s\r\n" %(
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

  def _read_write(self, soc, max_idling=20, local=False):
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
      if count == max_idling: break

  do_HEAD = do_GET
  do_POST = do_GET
  do_PUT  = do_GET
  do_DELETE=do_GET

  def log_message(self, format, *args):
    self.server.logger.info("%s %s", self.address_string(), format % args)

  def log_error(self, format, *args):
    self.server.logger.error("%s %s", self.address_string(), format % args)


class ThreadingHTTPServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
  def __init__(self, server_address, request_handler_class):
    BaseHTTPServer.HTTPServer.__init__(
      self, server_address, request_handler_class)
    self.logger = self.create_logger()

  def create_logger(self):
    result = logging.getLogger("TinyHTTPProxy")
    result.setLevel(logging.INFO)
    hldr = logging.StreamHandler()
    format = logging.Formatter("[%(asctime)-12s.%(msecs)03d] "
      "%(levelname)-8s {%(name)s %(threadName)s}"
      " %(message)s",
      "%Y-%m-%d %H:%M:%S")
    hldr.setFormatter(format)
    result.addHandler(hldr)
    return result


def usage(msg=None):
  if msg: print msg
  print sys.argv[0], "[-p port] [-l logfile] [-dh] [allowed_client_name ...]]"
  print
  print "   -p     - Port to bind to"
  print


def handler(signo, frame):
  while frame and isinstance(frame, FrameType):
    if frame.f_code and isinstance(frame.f_code, CodeType):
      if "exit_event" in frame.f_code.co_varnames:
        frame.f_locals["exit_event"].set()
        return
    frame = frame.f_back


def main():
  PORT = 3128
  HOST = 'localhost'
  exit_event = threading.Event()

  try:
    opts, args = getopt.getopt(sys.argv[1:], "l:dhp:", [])
  except getopt.GetoptError, e:
    usage(str(e))
    return 1

  for opt, value in opts:
    # TODO: add support for the forward host and port through the command line
    if opt == "-p":
      PORT = int(value)
    else:
      usage()
      return 0

  signal(SIGINT, handler)
  server_address = (HOST, PORT)
  ProxyHandler.protocol = "HTTP/1.0"
  httpd = ThreadingHTTPServer(server_address, ProxyHandler)
  sockname = httpd.socket.getsockname()
  httpd.logger.info("Serving HTTP on", sockname[0], "port", sockname[1])
  active_threads_count = 0
  max_active_threads_count = 1000
  while not exit_event.isSet():
    try:
      httpd.handle_request()
      active_threads_count += 1
      if active_threads_count >= max_active_threads_count:
        httpd.logger.info("Number of active threads: %s",
          threading.activeCount())
        active_threads_count = 0
    except select.error, err:
      if err[0] == 4 and exit_event.isSet():
        pass
      else:
        httpd.logger.critical("Errno: %d - %s", err[0], err[1])
  httpd.logger.info("Server shutdown..")
  return 0


if __name__ == '__main__':
  sys.exit(main())
