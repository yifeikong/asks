__all__ = ['get_netloc_port', 'requote_uri', 'timeout_manager', 'send_event',
           'recv_event']


import h11
from urllib.parse import quote
from functools import wraps

from anyio import fail_after

from .errors import RequestTimeout


async def timeout_manager(timeout, coro, *args):
    try:
        async with fail_after(timeout):
            return await coro(*args)
    except TimeoutError as e:
        raise RequestTimeout from e


def get_netloc_port(scheme, netloc):
    try:
        netloc, port = netloc.split(':')
    except ValueError:
        if scheme == 'https':
            port = '443'
        else:
            port = '80'
    except TypeError:
        raise RuntimeError('Something is goofed. Contact the author!')
    return netloc, port


# The unreserved URI characters (RFC 3986)
UNRESERVED_SET = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" +
                  "0123456789-._~")


def unquote_unreserved(uri):
    """Un-escape any percent-escape sequences in a URI that are unreserved
    characters. This leaves all reserved, illegal and non-ASCII bytes encoded.
    :rtype: str
    """
    parts = uri.split('%')
    for i in range(1, len(parts)):
        h = parts[i][0:2]
        if len(h) == 2 and h.isalnum():
            try:
                c = chr(int(h, 16))
            except ValueError:
                raise ValueError("Invalid percent-escape sequence: '%s'" % h)

            if c in UNRESERVED_SET:
                parts[i] = c + parts[i][2:]
            else:
                parts[i] = '%' + parts[i]
        else:
            parts[i] = '%' + parts[i]
    return ''.join(parts)


def requote_uri(uri):
    """Re-quote the given URI.
    This function passes the given URI through an unquote/quote cycle to
    ensure that it is fully and consistently quoted.
    :rtype: str
    """
    safe_with_percent = "!#$%&'()*+,/:;=?@[]~"
    safe_without_percent = "!#$&'()*+,/:;=?@[]~"
    try:
        # Unquote only the unreserved characters
        # Then quote only illegal characters (do not quote reserved,
        # unreserved, or '%')
        return quote(unquote_unreserved(uri), safe=safe_with_percent)
    except ValueError:
        # We couldn't unquote the given URI, so let's try quoting it, but
        # there may be unquoted '%'s in the URI. We need to make sure they're
        # properly quoted so they do not cause issues elsewhere.
        return quote(uri, safe=safe_without_percent)


def processor(gen):
    @wraps(gen)
    def wrapper(*args, **kwargs):
        g = gen(*args, **kwargs)
        next(g)
        return g
    return wrapper


async def send_event(sock, request_bytes, body_bytes, h11_connection):
    '''
    Takes a h11 request, body and connection, then shoots 'em off
    in to the ether.

    Args:
        sock (socket): the socket to be used for sending bytes.
        h11_req (h11.Request): the h11 request object.
        h11_body (h11.Data): the h11 request body object.
        hconnection (h11.Connection): the h11 connection object.
    '''
    await sock.send_all(h11_connection.send(request_bytes))
    if body_bytes is not None:
        await sock.send_all(h11_connection.send(body_bytes))
    await sock.send_all(h11_connection.send(h11.EndOfMessage()))


async def recv_event(sock, h11_connection, *, timeout=30, read_size=10000):
    '''
    Receive h11 event from given sock, and give back h11 response when we have
    enough data.

    Args:
        sock (socket): the socket to be used for receiving bytes.
        hconnection (h11.Connection): the h11 connection object.
        timeout (int or float): seconds before timeout.
        read_size (int or float): read size for each read call.
    '''
    while True:
        event = h11_connection.next_event()
        if event is h11.NEED_DATA:
            data = await timeout_manager(timeout, sock.receive_some, read_size)
            h11_connection.receive_data(data)
            continue
        return event
