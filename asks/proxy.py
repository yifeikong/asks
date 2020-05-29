__all__ = ['Proxy']

import warnings
from urllib.parse import urlparse

from .auth import BasicAuth
from .errors import ProxyError


class Proxy:

    def __init__(self, address, auth):
        self.address = address
        self.auth = auth

    @classmethod
    def parse(cls, proxy: str):
        '''
        This method removes the scheme in proxy address str and parse them into
        host and port pairs.

        http proixes which also support the ``CONNECT`` method and SSL
        tunneling are commonly called https proxies. Which means they are able
        to proxify https traffic, (e.g. https://httpbin.org). But the
        handshake still happens between client and remote server, not between
        the client and proxy server.

        So the correct form for https_proxy would be `http://example.com:3128`,
        NOT `https://example.com:3128`.

        There do exist some proxy servers which are capable of SSL
        handshake between client and proxy server. technically, these proxy
        servers should be represented as `https://example.com:3128`. However,
        these proxy servers are rarely used, we do not support it here.

        Some people have a misunderstanding of these proxies, when they
        use `https://example.com:3128`, most of the times, they mean the former
        proxy server, here we just ignores(but warns about) the scheme and use
        the host and port given.

        Args:
            proxies (str): proxy location to be ret.

        e.g.
            'http://foo:bar@10.0.0.1:3128' =>

            Proxy(address=('10.0.0.1', 3128), username='foo', password='bar')

            'https://10.0.0.1:3128' =>

            Proxy(address=('10.0.0.1', 3128), username=None, password=None)
        '''
        if not proxy:
            return None
        parsed = urlparse(proxy)
        if parsed.scheme == 'https':
            warnings.warn("only ssl tunnelling https proxy is supported, "
                          "https scheme in proxy address are considered "
                          "as http, ssl-between-client-and-proxy kind of "
                          "https proxy are not supported")
        if parsed.port is None:
            raise ProxyError('proxy server must have a port')
        if parsed.username is None:
            auth = None
        else:
            auth = BasicAuth((parsed.username, parsed.password),
                             header_name="Proxy-Authorization")
        return cls((parsed.hostname, parsed.port), auth)
