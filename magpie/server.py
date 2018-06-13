from SimpleHTTPServer import SimpleHTTPRequestHandler
from BaseHTTPServer import HTTPServer
import SocketServer
import urllib
import posixpath
import os


class RootedHTTPServer(HTTPServer):

    def __init__(self, base_path, *args, **kwargs):
        HTTPServer.__init__(self, *args, **kwargs)
        self.RequestHandlerClass.base_path = base_path


class RootedHTTPRequestHandler(SimpleHTTPRequestHandler):

    def translate_path(self, dir_path):
        dir_path = posixpath.normpath(urllib.unquote(dir_path))
        words = dir_path.split('/')
        words = filter(None, words)
        dir_path = self.base_path
        for word in words:
            drive, word = os.path.splitdrive(word)
            head, word = os.path.split(word)
            if word in (os.curdir, os.pardir):
                continue
            dir_path = os.path.join(dir_path, word)
        return dir_path


class DirectoryServer(object):
    def __init__(self, dir_path, port, ServerClass=RootedHTTPServer, HandlerClass=RootedHTTPRequestHandler):
        self.server_address = ('', int(port))
        self.http_handler = ServerClass(dir_path, self.server_address, HandlerClass)
        self.server_url, self.server_port = self.http_handler.socket.getsockname()

    def serve_forever(self):
        self.http_handler.serve_forever()
