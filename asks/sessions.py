'''
The disparate session (Session) is for making requests to multiple locations.
'''

from abc import ABCMeta, abstractmethod
from copy import copy
from functools import partialmethod
from urllib.parse import urlparse, urlunparse
import ssl

import h11
from h11 import RemoteProtocolError
from anyio import connect_tcp, create_semaphore

from .cookie_utils import CookieTracker
from .errors import BadHttpResponse, RequestTimeout, ProxyError
from .req_structs import SocketQ
from .request_object import RequestProcessor
from .utils import get_netloc_port, timeout_manager, send_event, recv_event
from .proxy import Proxy

__all__ = ['Session']


class BaseSession(metaclass=ABCMeta):
    '''
    The base class for asks' sessions.
    Contains methods for creating sockets, figuring out which type of
    socket to create, connecting the proxy, and all of the HTTP
    methods ('GET', 'POST', etc.)
    '''

    def __init__(self, headers=None, ssl_context=None, proxy=None):
        '''
        Args:
            headers (dict): Headers to be applied to all requests.
                headers set by http method call will take precedence and
                overwrite headers set by the headers arg.
            ssl_context (ssl.SSLContext): SSL context to use for https connections.
            proxy (str): proxy address to use for all requests.
        '''
        if headers is not None:
            self.headers = headers
        else:
            self.headers = {}

        self.ssl_context = ssl_context
        self.proxy = Proxy.parse(proxy)
        self.encoding = None
        self.source_address = None
        self._cookie_tracker = None

    @property
    @abstractmethod
    def sema(self):
        """
        A semaphore-like context manager.
        """
        ...

    async def _open_connection_http(self, location):
        '''
        Creates a normal async socket, returns it.
        Args:
            location (tuple(str, int)): A tuple of net location (eg
                '127.0.0.1' or 'example.org') and port (eg 80 or 25000).
        '''
        sock = await connect_tcp(location[0], location[1], bind_host=self.source_address)
        sock._active = True
        return sock

    async def _open_connection_https(self, location):
        '''
        Creates an async SSL socket, returns it.
        Args:
            location (tuple(str, int)): A tuple of net location (eg
                '127.0.0.1' or 'example.org') and port (eg 80 or 25000).
        '''
        sock = await connect_tcp(location[0],
                                 location[1],
                                 ssl_context=self.ssl_context or ssl.SSLContext(),
                                 bind_host=self.source_address,
                                 autostart_tls=True)
        sock._active = True
        return sock

    async def _prepare_https_proxy(self, sock, address):
        '''
        To use https-tunnelling http proxies, we first ``CONNECT`` the proxy
        server, the server should open a SSL tunnel for us.

            CONNECT httpbin.org:443 HTTP/1.1
            Host: httpbin.org:443

        Then we must do TLS handshake and so on, to do this we must
        wrap raw socket into a secure one.

        Args:
            sock (SockeStream) raw socket to proxy server
            address (tuple(str, int)) remote server address, not proxy
        '''
        host = '{}:{}'.format(address[0], address[1])
        connect_req = h11.Request(method='CONNECT',
                                  target=host,
                                  headers=[('Host', host),
                                           ('Proxy-Connection', 'Keep-Alive')])
        hconnection = h11.Connection(our_role=h11.CLIENT)
        await send_event(sock, connect_req, None, hconnection)
        try:
            rsp = await recv_event(sock, hconnection)
            if rsp.status_code == 200:
                # server_name is crucial here, it means we handshake
                # with remote server, not the proxy
                sock._server_hostname = address[0]
                sock = await sock.start_tls()
                sock._active = True
                return sock
            else:
                raise ProxyError('status code {}, message {}'
                                 .format(rsp.status_code, rsp.message))
        except RemoteProtocolError as e:
            raise ProxyError('Can not connect to proxy server') from e

    async def _connect(self, scheme, address, proxy):
        '''
        Simple enough stuff to figure out where we should connect, and creates
        the appropriate connection.
        '''
        if proxy:
            # always connect the proxy without tls
            sock = await self._open_connection_http(proxy.address)
            # If we are visiting a https url, start a tunnel via the proxy.
            # First open a http(non-SSL) connection to proxy server
            # for `CONNECT` method, which instructs the proxy server to open
            # a SSL tunnel for us
            if scheme == 'https':
                sock = await self._prepare_https_proxy(sock, address)
                # the tunnel is bound to both the proxy and remote host
                sock.host = (address, proxy.address)
                sock.proxy_type = 'https'
            else:
                # any other connection to this proxy could reuse the same socket
                sock.host = proxy.address
                sock.proxy_type = 'http'
        else:  # https
            if scheme == 'https':
                sock = await self._open_connection_https(address)
            else:
                sock = await self._open_connection_http(address)
            sock.host = address
            sock.proxy_type = None
        return sock

    async def request(self, method, url=None, *, path='', retries=1,
                      connection_timeout=60, **kwargs):
        '''
        This is the template for all of the `http method` methods for
        the Session.

        Args:
            method (str): A http method, such as 'GET' or 'POST'.
            url (str): The url the request should be made to.
            path (str): An optional kw-arg for use in Session method calls,
                for specifying a particular path. Usually to be used in
                conjunction with the base_location/endpoint paradigm.
            kwargs: Any number of the following:
                        data (dict or str): Info to be processed as a
                            body-bound query.
                        params (dict or str): Info to be processed as a
                            url-bound query.
                        headers (dict): User HTTP headers to be used in the
                            request.
                        encoding (str): The str representation of the codec to
                            process the request under.
                        json (dict): A dict to be formatted as json and sent in
                            the request body.
                        files (dict): A dict of `filename:filepath`s to be sent
                            as multipart.
                        cookies (dict): A dict of `name:value` cookies to be
                            passed in request.
                        callback (func): A callback function to be called on
                            each bytechunk of of the response body.
                        timeout (int or float): A numeric representation of the
                            longest time to wait on a complete response once a
                            request has been sent.
                        retries (int): The number of attempts to try against
                            connection errors.
                        max_redirects (int): The maximum number of redirects
                            allowed.
                        persist_cookies (True or None): Passing True
                            instantiates a CookieTracker object to manage the
                            return of cookies to the server under the relevant
                            domains.
                        auth (child of AuthBase): An object for handling auth
                            construction.
                        proxy (str): Proxy to be used for sending requests

        When you call something like Session.get() or asks.post(), you're
        really calling a partial method that has the 'method' argument
        pre-completed.
        '''
        proxy = Proxy.parse(kwargs.pop("proxy", None)) or self.proxy
        timeout = kwargs.get('timeout', None)
        req_headers = kwargs.pop('headers', None)

        if self.headers is not None:
            headers = copy(self.headers)
        if req_headers is not None:
            headers.update(req_headers)
        req_headers = headers

        async with self.sema:
            if url is None:
                url = self._make_url() + path

            retry = False

            sock = None
            try:
                sock = await timeout_manager(
                    connection_timeout, self._grab_connection, url, proxy)
                port = sock.port

                req_obj = RequestProcessor(
                    self,
                    method,
                    url,
                    port,
                    headers=req_headers,
                    encoding=self.encoding,
                    sock=sock,
                    persist_cookies=self._cookie_tracker,
                    proxy=proxy,
                    **kwargs
                )

                try:
                    if timeout is None:
                        sock, r = await req_obj.make_request()
                    else:
                        sock, r = await timeout_manager(timeout, req_obj.make_request)
                except BadHttpResponse:
                    if timeout is None:
                        sock, r = await req_obj.make_request()
                    else:
                        sock, r = await timeout_manager(timeout, req_obj.make_request)

                if sock is not None:
                    try:
                        if r.headers['connection'].lower() == 'close' and not proxy:
                            sock._active = False
                            await sock.close()
                    except KeyError:
                        pass
                    await self.return_to_pool(sock)

            # ConnectionErrors are special. They are the only kind of exception
            # we ever want to suppress. All other exceptions are re-raised or
            # raised through another exception.
            except ConnectionError as e:
                if retries > 0:
                    retry = True
                    retries -= 1
                else:
                    raise e

            except Exception as e:
                if sock:
                    await self._handle_exception(e, sock)
                raise

            # any BaseException is considered unlawful murder, and
            # Session.cleanup should be called to tidy up sockets.
            except BaseException as e:
                if sock:
                    await sock.close()
                raise e

        if retry:
            return (await self.request(method,
                                       url,
                                       path=path,
                                       retries=retries,
                                       headers=headers,
                                       **kwargs))

        return r

    # These be the actual http methods!
    # They are partial methods of `request`. See the `request` docstring
    # above for information.
    get = partialmethod(request, 'GET')
    head = partialmethod(request, 'HEAD')
    post = partialmethod(request, 'POST')
    put = partialmethod(request, 'PUT')
    delete = partialmethod(request, 'DELETE')
    options = partialmethod(request, 'OPTIONS')

    async def _handle_exception(self, e, sock):
        """
        Given an exception, we want to handle it appropriately. Some exceptions we
        prefer to shadow with an asks exception, and some we want to raise directly.
        In all cases we clean up the underlying socket.
        """
        if isinstance(e, (RemoteProtocolError, AssertionError)):
            await sock.close()
            raise BadHttpResponse('Invalid HTTP response from server.') from e

        if isinstance(e, Exception):
            await sock.close()
            raise e

    @abstractmethod
    def _make_url(self):
        """
        A method who's result is concated with a uri path.
        """
        ...

    @abstractmethod
    async def _grab_connection(self, url: str, proxy: Proxy):
        """
        A method that will return a socket-like object.
        """
        ...

    @abstractmethod
    async def return_to_pool(self, sock):
        """
        A method that will accept a socket-like object.
        """
        ...


class Session(BaseSession):
    '''
    The Session class, for handling piles of requests.

    This class inherits from BaseSession, where all of the 'http method'
    methods are defined.
    '''

    def __init__(self,
                 base_location=None,
                 endpoint=None,
                 headers=None,
                 proxy=None,
                 encoding='utf-8',
                 persist_cookies=None,
                 ssl_context=None,
                 connections=1):
        '''
        Args:
            encoding (str): The encoding asks'll try to use on response bodies.
            persist_cookies (bool): Passing True turns on browserishlike
                stateful cookie behaviour, returning cookies to the host when
                appropriate.
            connections (int): The max number of concurrent connections to the
                host asks will allow its self to have. The default number of
                connections is 1. You may increase this value as you see fit.
        '''
        super().__init__(headers, ssl_context, proxy)
        self.encoding = encoding
        self.base_location = base_location
        self.endpoint = endpoint

        if persist_cookies is True:
            self._cookie_tracker = CookieTracker()
        else:
            self._cookie_tracker = persist_cookies

        self._conn_pool = SocketQ()
        self._http_proxy_conn_pool = SocketQ()
        self._https_proxy_conn_pool = SocketQ()

        self._sema = None
        self._connections = connections

    @property
    def sema(self):
        if self._sema is None:
            self._sema = create_semaphore(self._connections)
        return self._sema

    def _checkout_connection(self, scheme, address, proxy):
        '''
        Trying to pull a socket from connection pool, return None if not there.

        Args:
            scheme (str): http or https
            netloc (str): netloc, contains port
            proxy (Proxy): proxy instance to use
        '''
        try:
            if proxy:
                if scheme == 'http':
                    index = self._http_proxy_conn_pool.index(proxy.address)
                    sock = self._http_proxy_conn_pool.pull(index)
                else:
                    index = self._https_proxy_conn_pool.index(address)
                    sock = self._https_proxy_conn_pool(index)
            else:
                index = self._conn_pool.index(address)
                sock = self._conn_pool(index)
        except ValueError:
            return None

        return sock

    async def return_to_pool(self, sock):
        if not sock._active:
            return

        if sock.proxy_type == 'http':
            self._http_proxy_conn_pool.appendleft(sock)
        elif sock.proxy_type == 'https':
            self._https_proxy_conn_pool.appendleft(sock)
        else:
            self._conn_pool.appendleft(sock)

    async def _grab_connection(self, url: str, proxy: Proxy):
        '''
        The connection pool handler. Returns a connection
        to the caller. If there are no connections ready, and
        as many connections checked out as there are available total,
        we yield control to the event loop.

        If there is a connection ready or space to create a new one, we
        pop/create it, register it as checked out, and return it.

        Args:
            url (str): breaks the url down and uses the top level location
                info to see if we have any connections to the location already
                lying around.
            proxy (Proxy): proxy to use in sending requests.
        '''
        scheme, netloc, _, _, _, _ = urlparse(url)
        address = get_netloc_port(scheme, netloc)

        sock = self._checkout_connection(scheme, address, proxy)

        if sock is None:
            sock = await self._connect(scheme, address, proxy)

        return sock

    def _make_url(self):
        '''
        Puts together the hostloc and current endpoint for use in request uri.
        '''
        return (self.base_location or '') + (self.endpoint or '')

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self.close()

    async def close(self):
        await self._conn_pool.free_pool()
