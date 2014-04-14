#!/usr/bin/python

"""
jCSRF Proxy.

This module implements GET and POST methods on BaseHTTPServer. 

GET is of three types:
1. Normal GET request. Simply forwarded to the proxy, and a new token C
   is added if it was not provided in the request.
2. Token request: if the get request provides a special CSRF header and
  an argument S, create a token Pst = AES(C|S) and return it along with
  Set-Cookie: C
3. Special resource: files under /jcsrf_static/ are served 
  directly from the proxy.

POST request logic: find either co-token or so-token in data or
X-No-CSRF header.
so-token:
  match it with C.
co-token:
  decrypt it and check that C matches and S is allowed. Otherwise,
  strip cookies or deny request.
X-No-CSRF:
  so-request, allow

Notes:
proxy does not support chucked encoding, persistent connections and caching
also does not fully support http 1.1, see next line to fix
look http://publib.boulder.ibm.com/httpserv/manual60/env.html#special
for more options. most of these unsupported features are taken care of by removing
headers, but i think there was something to do in the browser and in
apache as well.
"""

#TODO: manage the jcsrf-token, then we can debug everything

__version__ = "1.0"

TARGET_SERVER = "localhost"
TARGET_PORT = 80

import urllib
import BaseHTTPServer, select, socket, SocketServer, urlparse
import re
import logging
import sys 
import os
import base64
import getopt
from Crypto.Cipher import AES
from sys import argv
import cPickle
import signal
import Cookie
import random
import string

ROOT_UID   = 0
BLOCK_SIZE = 16
PADDING    = '\0'
csrf_enforced = True
nofirewall = False
strip_cookies = False
secretKey = None

try:
    import psyco
    psyco.full()
except ImportError:
    pass

# CTRL+c
def quit_handler(sig, frame):
    print "\nClosing Proxy"
    if not nofirewall:
        os.system("iptables -F")
        os.system("iptables -F -t nat")
    sys.exit(0)
signal.signal(signal.SIGINT, quit_handler)


# CTRL+\
def switch_handler(sig, frame):
    global csrf_enforced
    if csrf_enforced:
        csrf_enforced = False
        logging.info("Disabling Protection")
    else:
        csrf_enforced = True
        logging.info("Enabling Protection")
signal.signal(signal.SIGQUIT, switch_handler)



class JCSRFProxyHandler (BaseHTTPServer.BaseHTTPRequestHandler):
    "jCSRF HTTP Proxy, based on TinyHTTPProxy"
    __base = BaseHTTPServer.BaseHTTPRequestHandler
    __base_handle = __base.handle

    server_version = "jCSRF/" + __version__
    rbufsize = 0                        # self.rfile Be unbuffered


    def _connect_to(self, soc):
        host_port = TARGET_SERVER, TARGET_PORT
        try:
            soc.connect(host_port)
        except socket.error, arg:
            try: msg = arg[1]
            except: msg = arg
            self.send_error(404, msg)
            return 0
        return 1


    def do_GET(self):
        """
        Decides whether to relay request, send token or serve special jcsrf content.
        """
        (scm, netloc, path, params, query, fragment) = urlparse.urlparse(
            self.path, 'http')
        if scm != 'http' or fragment:
            self.send_error(400, "bad url %s" % self.path)
            return

        logging.info("GET: %s", self.path)

        self.cookies = Cookie.BaseCookie()
        if self.headers.has_key("Cookie"):
            self.cookies.load(self.headers["Cookie"])
            #logging.debug("Request Cookies: %s", self.cookies)

        if self.headers.has_key("X-No-Csrf") and \
                path.startswith("/jcsrf_token") and csrf_enforced:
            self.send_token()
        elif path.startswith("/jcsrf_static/") and csrf_enforced:
            self.serve_file(path.replace("/jcsrf_static/", ""))
        else:
            self.do_normalGET()

    def serve_file(self, f):
        """Serves the file f directly from the proxy"""
        if f in ["jcsrf.js", "jquery.js"]:
            self.send_string(open(f).read(), "text/javascript")
        elif f in ["jcsrf_iframe.html"]:
            self.send_string(open(f).read(), "text/html")
        else:
            self.send_error(403, "Access denied for static file %s" % f)


    def do_POST(self):
        """
        Check for either C-O compliance, S-O compliance or 
        X-No-CSRF.
        """        
        post_string = self.read_post()

        if self.headers.has_key("Cookie"):
            self.cookies = Cookie.BaseCookie()
            self.cookies.load(self.headers["Cookie"])
        else:
            self.cookies = None

        if self.headers.has_key("X-No-Csrf"):
            logging.debug("POST with csrf header, allow")
            return self.send_POST(post_string)

        if not csrf_enforced:
            logging.debug("Protection Disabled, allow")
            return self.send_POST(post_string)

        # let's find a token in the params
        if self.headers.has_key("Content-Type") and \
                "multipart" in self.headers["Content-Type"]:
            params = self.parse_mime(post_string)
        else:
            paramsRegex = "[\?&]?([^=&\?]+)=([^=&]+)"
            params = dict([(n, urllib.unquote_plus(v)) for n, v in \
                               (re.findall(paramsRegex, post_string))])
        logging.debug("Params: %s", params)

        if params.has_key("jcsrf-so-token"):
            valid = self.cookies["jcsrf-token"].value == params["jcsrf-so-token"]
        elif params.has_key("jcsrf-co-token"):
            #Assign IV and init cipher
            token = params["jcsrf-co-token"]
            initVector = token[0:BLOCK_SIZE]
            cipher = AES.new(secretKey, AES.MODE_CBC, initVector)
            token = token[BLOCK_SIZE:]
            temp = base64.b64decode(token)
            token = cipher.decrypt(temp).rstrip(PADDING)
            (cookie, origin) = cPickle.loads(token)
            valid = cookie == self.cookies["jcsrf-token"].value and \
                    origin == "localhost" #TODO: proper wlist support
        else:
            logging.error("No token found")
            valid = False

        if not valid:
            if strip_cookies:
                logging.error("Invalid token, stripping cookies")
                del self.headers["Cookie"]
            else:
                return self.send_error(403, "Invalid token, access denied")
        
        if post_string == "":
            # are POST requests with empty body even legal?
            return self.send_error(403, "Cannot relay data, error")

        self.send_POST(post_string)


    def send_POST(self, post_string):
        """Dispatches POST request to the server"""
        self.command = "POST"
        (scm, netloc, path, params, query, fragment) = urlparse.urlparse(
            self.path, 'http')

        logging.info("POST: %s", self.path)
        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            if self._connect_to(soc):
                soc.send("%s %s %s\r\n" % (
                    self.command,
                    urlparse.urlunparse(('', '', path, params, query, '')),
                    self.request_version))
                # remove unsupported capabilities
                self.headers['Connection'] = 'close'
                self.headers['Cache-Control'] = 'no-cache'
                del self.headers['Proxy-Connection']
                del self.headers['Accept-Encoding']
                del self.headers['Keep-Alive']
                del self.headers['Accept-Encoding']
                del self.headers['Age']
                del self.headers['If-Modified-Since']
                del self.headers['If-None-Match']
                del self.headers['ETag']
                for key_val in self.headers.items():
                    soc.send("%s: %s\r\n" % key_val)
                soc.send("\r\n")
                self.send_post(post_string, soc)
                response = self.read_response(soc)
                if csrf_enforced:
                    response = self.inject_js(response)
                response = self.write_length(response)
                self.relay_response(response)

        finally:
            soc.close()
            self.connection.close()


    def do_normalGET(self):
        """Relays the GET request like a normal proxy, but also
        injects our script in the page head"""

        (scm, netloc, path, params, query, fragment) = urlparse.urlparse(
            self.path, 'http')
        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            if self._connect_to(soc):
                soc.send("%s %s %s\r\n" % (
                        self.command,
                        urlparse.urlunparse(('', '', path, params, query, '')),
                        self.request_version))
                self.headers['Connection'] = 'close'
                self.headers['Cache-Control'] = 'no-cache'
                del self.headers['Proxy-Connection']
                del self.headers['Accept-Encoding']
                del self.headers['Keep-Alive']
                del self.headers['Age']
                del self.headers['If-Modified-Since']
                del self.headers['If-None-Match']
                del self.headers['ETag']
                for key_val in self.headers.items():
                    soc.send("%s: %s\r\n" % key_val)
                soc.send("\r\n")
                response = self.read_response(soc)
                if csrf_enforced:
                    response = self.inject_js(response)
                    if not self.cookies.has_key("jcsrf-token"):
                        response = self.inject_cookie(response)
                response = self.write_length(response)
                self.relay_response(response)
        finally:
            soc.close()
            self.connection.close()


    def read_response(self, soc, max_idling=20):
        """Reads the server response"""
        iw = [soc]
        ow = []
        count = 0
        body = ""
        while 1:
            count += 1
            (ins, _, exs) = select.select(iw, ow, iw, 3)
            if exs: break
            if len(ins) == 0:
                continue
            try:
                data = ins[0].recv(131072)
            except socket.error:
                break
            if data:
                body += data
                count = 0
            if count == max_idling: break
        return body


    def relay_response(self, response, max_idling=20):
        """Sends the response back to the client"""
        iw = []
        ow = [self.connection]
        count = 0
        sent = 0
        total_sent = 0
        while 1:
            count += 1
            (_, ons, exs) = select.select(iw, ow, ow, 3)
            if exs: break
            if len(ons) == 0:
                continue
            try:
                sent = ons[0].send(response)
                total_sent += sent
            except socket.error:
                break
            if total_sent >= len(response): break
            #if read == 0: break
            if count == max_idling: break


    def read_post(self):
        """Reads the post string from the client"""
        length = self.headers["Content-Length"]
        (ins, _, exs) = select.select([self.rfile], [], [], 0)
        if ins and length:
            data = self.rfile.read(int(length))
        else:
            logging.error("Reading POST data failed")
            data = ""
        logging.debug("POST Body: %s", data)
        return data


    def send_post(self, post_string, soc, max_idling=20):
        """Sends the post string to the server"""
        iw = []
        ow = [soc]
        count = 0
        total_sent = 0
        while 1:
            count += 1
            (_, ons, exs) = select.select(iw, ow, ow, 3)
            if exs:
                break
            if len(ons) == 0:
                continue
            try:
                sent = ons[0].send(post_string)
                total_sent += sent
            except socket.error:
                logging.error("Sending POST failed")
                break
            if total_sent >= len(post_string): break
            #if read == 0: break
            if count == max_idling: break


    def send_token(self, max_idling=20):
        """Sends the c-o token to the client."""
        origin = re.search("\?origin=([^&=#]+)", self.path).group(1)
        cookie = self.cookies["jcsrf-token"].value
        data = (cookie, origin)
        buf = cPickle.dumps(data)
        buf += ((BLOCK_SIZE - len(buf)) % BLOCK_SIZE) * PADDING
        #Generate IV and init cipher
        initVector = base64.b64encode(os.urandom(12))
        cipher = AES.new(secretKey, AES.MODE_CBC, initVector)
        #Encrypt nonce
        buf = cipher.encrypt(buf)
        buf = base64.b64encode(buf)
        buf = initVector + buf
        self.send_string(buf, "text/plain")

    def send_string(self, s, content_type, max_idling=20):
        """Send the string s directly from the proxy."""
        headers = """HTTP/1.0 200 OK
Content-Type: %s
Content-Length: %s
""" % (content_type, len(s))
        response = headers.replace("\n", "\r\n") + "\r\n" + s
        if not self.cookies.has_key("jcsrf-token"):
            response = self.inject_cookie(response)
        #logging.debug("Sending string as response:\n\n%s\n\n" % response)
        (ip, port) = self.client_address  
        iw = []
        ow = [self.connection]
        count = 0
        read = 0
        total_sent = 0
        while 1:
            count += 1
            (_, ons, exs) = select.select(iw, ow, ow, 3)
            if exs: break
            if len(ons) == 0:
                continue
            try:
                read = ons[0].send(response)
                total_sent += read
            except socket.error:
                break
            if total_sent >= len(response): break
            if read == 0: break
            if count == max_idling: break
 
    def inject_js(self, response):
        """Adds jcsrf javascript code to the HTML response for interposition"""
        header_lines = response.split("\r\n\r\n")[0].split("\r\n")
        headers = dict([(h.split(": ", 1)[0].lower(), h.split(": ", 1)[1]) \
                            for h in header_lines if ": " in h]) 
        #TODO: this stuff is probably useless, just use a regex

        #Check if 30x message
        status_re = re.compile(r'HTTP/\d+\.\d+ 30[1-4] (.*?)\r\n')
        match = status_re.match(response[:40])
        if match:
            logging.info("HTTP Redirection status. Not injecting jcsrf")
            return response
        if headers.get("content-type", "").split(";")[0] != "text/html":
            logging.debug("%s has content type %s, skip", 
                          self.path, headers.get("content-type"))
            return response

        injection = '<script src="/jcsrf_static/jcsrf.js"></script>\n'
        if "<head>" in response.lower():
            return re.sub("<head>", "<head>" + injection, response,
                          flags=re.IGNORECASE)
        else:
            return re.sub("<body", "<head>" + injection + "<head><body",
                          response, flags=re.IGNORECASE)
 
    def inject_cookie(self, response):
        """Adds a set-cookie header with a random identifier"""
        #TODO: what if there is another set-cookie header already?
        token = "".join([random.choice(string.letters + string.digits) \
                             for i in range(20)])
        logging.debug("Adding cookie %s", token)
        return response.replace("\r\n\r\n", "\r\nSet-Cookie: jcsrf-token=%s; Path=/\r\n\r\n" % token)

    def write_length(self, response):
        "Adjusts the content-length header."
        length = len(response.split("\r\n\r\n")[1])
        original = response
        response = re.sub("content-length: \d+",
                          "Content-Length: %d" % length, response, flags=re.IGNORECASE)
        if response == original:
            response = response.replace(
                "\r\n\r\n", "\r\nContent-Length: %d\r\n\r\n" % length)
        return response

    def parse_mime(self, buf):
        "Parse MIME messages into a dict."
        boundary = "--" + self.headers["Content-Type"].split("boundary=")[1]
        boundary = re.search(r"[^-]+", boundary).group(0)
        res = {}
        entries = re.split("-+" + boundary + "(?:-+)?(?:\r\n)?", buf)
        for entry in entries[1:-1]:
            lines = entry.splitlines()
            name = re.search('name=\"([^;\"]+)\"', lines[0])
            if name:
                value = lines[-1]
                res[name.group(1)] = value
        return res

class ThreadingHTTPServer (SocketServer.ThreadingMixIn,
                           BaseHTTPServer.HTTPServer): pass

def usage():
    """Prints the usage"""
    print "proxy.py port [--verbose] [--key=n] [--nofirewall]"
    return


def main():
    """Starts the proxy using the shell arguments"""
    global secretKey, nofirewall

    if os.geteuid() != ROOT_UID:
        print 'Proxy requires root priveleges. Invoke as:'
        usage()
        sys.exit(0)

    try:
        opts, _ = getopt.getopt(sys.argv[2:], None,
                                   ["verbose", "key=", "port=", "nofirewall"])
    except getopt.GetoptError, err:
        logging.error(str(err))
        usage()
        sys.exit(2)
    loglevel = logging.ERROR
    for o, a in opts:
        if o == "--verbose":
            loglevel = logging.DEBUG
        elif o == "--key":
            secretKey = a
        elif o == "--nofirewall":
            nofirewall = True
        else:
            assert False, "unhandled option"
            usage()
            sys.exit(2)

    if not nofirewall:
        os.system("iptables-restore < iptables-proxy")
    #Initialize logging
    logging.basicConfig(level=loglevel,
                        format='[%(levelname)s] %(message)s')
    #Set the secret key
    if secretKey:
        logging.debug("key forced to %s" % argv[2])
    else:
        secretKey = os.urandom(BLOCK_SIZE)
    #Start proxy
    while 1:
        try:
            BaseHTTPServer.test(JCSRFProxyHandler, ThreadingHTTPServer)
        except select.error:
            pass
    return


if __name__ == '__main__':
    main()
