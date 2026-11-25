#!/usr/bin/env python3
"""Public DNS server that points the offline vendor P2P hostnames at your own natserver.py.

Anyone can set a recorder's or phone's DNS to this server:
- Names in OVERRIDE_NAMES get an A record = OVERRIDE_IP.
- Everything else is forwarded to UPSTREAM.

Being an open resolver, it is hardened against DNS amplification abuse:
- UDP is rate limited per source IP (token bucket RATE/s, BURST); excess queries are dropped silently.
- UDP answers over 512 bytes are replaced by a truncated reply, so big answers only go over TCP,
  which can't be spoofed. ANY queries are refused.
- TCP 53 and DNS over TLS (853, for Android "Private DNS") need a handshake, so they aren't limited.
"""
import os, socket, ssl, struct, threading, time

OVERRIDE_IP = os.environ.get("OVERRIDE_IP", "127.0.0.1")
OVERRIDE_NAMES = {n.strip().lower().rstrip(".") for n in os.environ.get(
    "OVERRIDE_NAMES", "admtecvozp2p.com.br,www.admtecvozp2p.com.br").split(",") if n.strip()}
UPSTREAM = (os.environ.get("UPSTREAM", "8.8.8.8"), int(os.environ.get("UPSTREAM_PORT", "53")))
PORT = int(os.environ.get("DNS_PORT", "53"))
BIND = os.environ.get("DNS_BIND", "0.0.0.0")    # set to the NIC address if systemd-resolved holds 127.0.0.53:53
RATE = float(os.environ.get("RATE", "20"))      # UDP queries per second per source IP
BURST = float(os.environ.get("BURST", "100"))
# DNS over TLS: needs a cert for a hostname you own. With systemd LoadCredential the files appear in
# $CREDENTIALS_DIRECTORY, so relative names are looked up there.
_cred = os.environ.get("CREDENTIALS_DIRECTORY", "")
DOT_CERT = os.path.join(_cred, os.environ.get("DOT_CERT", "")) if os.environ.get("DOT_CERT") else ""
DOT_KEY = os.path.join(_cred, os.environ.get("DOT_KEY", "")) if os.environ.get("DOT_KEY") else ""
DOT_PORT = int(os.environ.get("DOT_PORT", "853"))

A, AAAA, ANY, IN = 1, 28, 255, 1
NOERROR, SERVFAIL, REFUSED = 0, 2, 5
UDP_MAX = 512


def parse_question(q):
    """Return (name, qtype, end offset) of the first question, or None if malformed."""
    if len(q) < 12 or struct.unpack_from(">H", q, 4)[0] != 1:
        return None
    i, labels = 12, []
    while i < len(q) and q[i]:
        n = q[i]
        if n & 0xC0 or i + 1 + n > len(q):        # no compression in queries
            return None
        labels.append(q[i + 1:i + 1 + n].decode("ascii", "replace"))
        i += 1 + n
    if i + 5 > len(q):
        return None
    qtype, _qclass = struct.unpack_from(">HH", q, i + 1)
    return ".".join(labels).lower(), qtype, i + 5


def answer(q, rcode, ip=None, tc=False):
    """Reply to query q echoing its question; with ip add one A record; tc sets the truncated bit."""
    _name, _qtype, end = parse_question(q)
    rd = q[2] & 0x01
    flags = 0x8000 | 0x0400 * (rcode == NOERROR and not tc) | 0x0200 * tc | rd << 8 | 0x0080 | rcode
    out = q[:2] + struct.pack(">HHHHH", flags, 1, 1 if ip else 0, 0, 0) + q[12:end]
    if ip:
        out += struct.pack(">HHHIH", 0xC00C, A, IN, 60, 4) + socket.inet_aton(ip)
    return out


class RateLimit:
    """Per-IP token bucket. ponytail: one dict + lock, pruned when large; fine for a few thousand qps."""

    def __init__(self, rate, burst):
        self.rate, self.burst, self.b, self.lock = rate, burst, {}, threading.Lock()

    def allow(self, ip, now=None):
        now = time.monotonic() if now is None else now
        with self.lock:
            tokens, last = self.b.get(ip, (self.burst, now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            ok = tokens >= 1
            self.b[ip] = (tokens - 1 if ok else tokens, now)
            if len(self.b) > 50000:   # forget idle clients (their bucket would be full again anyway)
                self.b = {k: v for k, v in self.b.items() if now - v[1] < self.burst / self.rate}
            return ok


def recv_exact(s, n):
    b = b""
    while len(b) < n:
        d = s.recv(n - len(b))
        if not d:
            raise ConnectionError("closed")
        b += d
    return b


def forward_tcp(q):
    """Forward over TCP so large answers are never truncated (TCP and DoT clients)."""
    with socket.create_connection(UPSTREAM, timeout=3) as up:
        up.sendall(struct.pack(">H", len(q)) + q)
        return recv_exact(up, struct.unpack(">H", recv_exact(up, 2))[0])


def forward_udp(q):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as up:
        up.settimeout(3)
        up.sendto(q, UPSTREAM)
        return up.recv(4096)


def resolve(q, forward):
    """Reply bytes for query q, or None to stay silent on garbage."""
    p = parse_question(q)
    if p is None:
        return None
    name, qtype, _ = p
    if name in OVERRIDE_NAMES:
        return answer(q, NOERROR, OVERRIDE_IP if qtype == A else None)   # AAAA etc: empty
    if qtype == ANY:
        return answer(q, REFUSED)
    try:
        return forward(q)
    except OSError:
        return answer(q, SERVFAIL)


def handle_udp(sock, q, addr):
    r = resolve(q, forward_udp)
    if r is None:
        return
    if len(r) > UDP_MAX:
        r = answer(q, NOERROR, tc=True)     # client retries over TCP
    sock.sendto(r, addr)


def handle_stream(conn):
    """TCP 53 / DNS over TLS (RFC 7766 / 7858): 2-byte length-prefixed messages on one connection."""
    try:
        conn.settimeout(10)
        while True:
            q = recv_exact(conn, struct.unpack(">H", recv_exact(conn, 2))[0])
            r = resolve(q, forward_tcp)
            if r is None:
                return
            conn.sendall(struct.pack(">H", len(r)) + r)
    except (OSError, ConnectionError, ValueError):
        pass
    finally:
        conn.close()


def serve_stream(port, bind="0.0.0.0", ctx=None):
    s = socket.create_server((bind, port))
    print("%s :%d" % ("DoT" if ctx else "TCP", port), flush=True)
    while True:
        c, _ = s.accept()

        def run(c=c):
            try:
                handle_stream(ctx.wrap_socket(c, server_side=True) if ctx else c)
            except (OSError, ssl.SSLError):
                c.close()
        threading.Thread(target=run, daemon=True).start()


def serve_dot(cert, key, port=DOT_PORT):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    serve_stream(port, ctx=ctx)


def serve(port=PORT, bind=BIND):
    threading.Thread(target=serve_stream, args=(port, bind), daemon=True).start()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((bind, port))
    limit = RateLimit(RATE, BURST)
    print("DNS :%d  %s -> %s  (public, UDP %g/s burst %g per IP)" % (
        port, sorted(OVERRIDE_NAMES), OVERRIDE_IP, RATE, BURST), flush=True)
    while True:
        q, addr = s.recvfrom(512)
        if limit.allow(addr[0]):            # checked before spawning a thread, so floods stay cheap
            threading.Thread(target=handle_udp, args=(s, q, addr), daemon=True).start()


if __name__ == "__main__":
    if DOT_CERT and DOT_KEY:
        threading.Thread(target=serve_dot, args=(DOT_CERT, DOT_KEY), daemon=True).start()
    serve()
