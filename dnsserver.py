#!/usr/bin/env python3
"""Tiny DNS server: points the dead vendor P2P hostnames at your own natserver.py.

- Names in OVERRIDE_NAMES get an A record = OVERRIDE_IP (for anyone).
- Every other query is forwarded to UPSTREAM, but only for clients in ALLOW (comma-separated
  IPs/CIDRs), so this never becomes an open resolver usable for DNS amplification attacks.
  Everyone else gets REFUSED, and devices fall back to their secondary DNS.
"""
import ipaddress, os, socket, ssl, struct, threading

OVERRIDE_IP = os.environ.get("OVERRIDE_IP", "127.0.0.1")
OVERRIDE_NAMES = {n.strip().lower().rstrip(".") for n in os.environ.get(
    "OVERRIDE_NAMES", "admtecvozp2p.com.br,www.admtecvozp2p.com.br").split(",") if n.strip()}
UPSTREAM = (os.environ.get("UPSTREAM", "8.8.8.8"), 53)
ALLOW = [ipaddress.ip_network(c.strip(), strict=False) for c in os.environ.get("ALLOW", "").split(",") if c.strip()]
PORT = int(os.environ.get("DNS_PORT", "53"))
BIND = os.environ.get("DNS_BIND", "0.0.0.0")    # set to the NIC address if systemd-resolved holds 127.0.0.53:53
# DNS over TLS for Android "Private DNS": needs a cert for a hostname you own. With systemd LoadCredential
# the files appear in $CREDENTIALS_DIRECTORY, so relative names are looked up there.
_cred = os.environ.get("CREDENTIALS_DIRECTORY", "")
DOT_CERT = os.path.join(_cred, os.environ.get("DOT_CERT", "")) if os.environ.get("DOT_CERT") else ""
DOT_KEY = os.path.join(_cred, os.environ.get("DOT_KEY", "")) if os.environ.get("DOT_KEY") else ""
DOT_PORT = int(os.environ.get("DOT_PORT", "853"))

A, AAAA, IN = 1, 28, 1
NOERROR, SERVFAIL, REFUSED = 0, 2, 5


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


def answer(q, rcode, ip=None):
    """Build a reply to query q echoing its question; with ip, add one A record."""
    _name, _qtype, end = parse_question(q)
    rd = q[2] & 0x01
    flags = 0x8000 | 0x0400 * (rcode == NOERROR) | rd << 8 | 0x0080 | rcode   # QR, AA, RD, RA, rcode
    out = q[:2] + struct.pack(">HHHHH", flags, 1, 1 if ip else 0, 0, 0) + q[12:end]
    if ip:
        out += struct.pack(">HHHIH", 0xC00C, A, IN, 60, 4) + socket.inet_aton(ip)
    return out


def allowed(ip):
    a = ipaddress.ip_address(ip)
    return any(a in n for n in ALLOW)


def recv_exact(s, n):
    b = b""
    while len(b) < n:
        d = s.recv(n - len(b))
        if not d:
            raise ConnectionError("closed")
        b += d
    return b


def forward_tcp(q):
    """Forward over TCP so large answers are never truncated (used for DoT clients)."""
    with socket.create_connection(UPSTREAM, timeout=3) as up:
        up.sendall(struct.pack(">H", len(q)) + q)
        return recv_exact(up, struct.unpack(">H", recv_exact(up, 2))[0])


def forward_udp(q):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as up:
        up.settimeout(3)
        up.sendto(q, UPSTREAM)
        return up.recv(4096)


def resolve(q, may_forward, forward):
    """Reply bytes for query q, or None to stay silent on garbage."""
    p = parse_question(q)
    if p is None:
        return None
    name, qtype, _ = p
    if name in OVERRIDE_NAMES:
        return answer(q, NOERROR, OVERRIDE_IP if qtype == A else None)   # AAAA etc: empty
    if not may_forward:
        return answer(q, REFUSED)
    try:
        return forward(q)
    except OSError:
        return answer(q, SERVFAIL)


def handle(sock, q, addr):
    r = resolve(q, allowed(addr[0]), forward_udp)
    if r:
        sock.sendto(r, addr)


def handle_dot(conn):
    """DNS over TLS (RFC 7858): 2-byte length-prefixed messages on one connection."""
    try:
        conn.settimeout(10)
        while True:
            q = recv_exact(conn, struct.unpack(">H", recv_exact(conn, 2))[0])
            # ponytail: DoT forwards for anyone (TCP, so no amplification); add rate limits if abused
            r = resolve(q, True, forward_tcp)
            if r is None:
                return
            conn.sendall(struct.pack(">H", len(r)) + r)
    except (OSError, ConnectionError, ValueError):
        pass
    finally:
        conn.close()


def serve_dot(cert, key, port=DOT_PORT):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    s = socket.create_server(("0.0.0.0", port), reuse_port=False)
    print("DoT :%d (forwarding for anyone over TLS)" % port, flush=True)
    while True:
        c, _ = s.accept()

        def run(c=c):
            try:
                handle_dot(ctx.wrap_socket(c, server_side=True))
            except (OSError, ssl.SSLError):
                c.close()
        threading.Thread(target=run, daemon=True).start()


def serve(port=PORT):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((BIND, port))
    print("DNS :%d  %s -> %s  forwarding for %s" % (port, sorted(OVERRIDE_NAMES), OVERRIDE_IP,
                                                   [str(n) for n in ALLOW] or "nobody"), flush=True)
    while True:
        q, addr = s.recvfrom(512)
        threading.Thread(target=handle, args=(s, q, addr), daemon=True).start()


if __name__ == "__main__":
    if DOT_CERT and DOT_KEY:
        threading.Thread(target=serve_dot, args=(DOT_CERT, DOT_KEY), daemon=True).start()
    serve()
