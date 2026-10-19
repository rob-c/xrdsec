"""An in-memory TLS handshake between two contexts, for tests."""

from __future__ import annotations

import ssl


def handshake(
    client: ssl.SSLContext, server: ssl.SSLContext, hostname: str = "localhost"
) -> ssl.SSLObject:
    """Run a handshake over memory BIOs; the client side once both finish.

    Raises whatever :meth:`ssl.SSLObject.do_handshake` raises on either side.
    """
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    s_in, s_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    c = client.wrap_bio(incoming, outgoing, server_hostname=hostname)
    s = server.wrap_bio(s_in, s_out, server_side=True)
    done: set[str] = set()
    for _ in range(20):
        for name, side, out, peer_in in (("c", c, outgoing, s_in), ("s", s, s_out, incoming)):
            if name not in done:
                try:
                    side.do_handshake()
                    done.add(name)
                except ssl.SSLWantReadError:
                    pass
            peer_in.write(out.read())
        if done == {"c", "s"}:
            return c
    raise AssertionError("the handshake did not finish")
