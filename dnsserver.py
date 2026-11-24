#!/usr/bin/env python3
"""Tiny DNS server: points the dead vendor P2P hostnames at your own natserver.py.

- Names in OVERRIDE_NAMES get an A record = OVERRIDE_IP (for anyone).
- Every other query is forwarded to UPSTREAM, but only for clients in ALLOW (comma-separated
  IPs/CIDRs), so this never becomes an open resolver usable for DNS amplification attacks.
  Everyone else gets REFUSED, and devices fall back to their secondary DNS.
"""
import ipaddress, os, socket, struct, threading

OVERRIDE_IP = os.environ.get("OVERRIDE_IP", "127.0.0.1")
OVERRIDE_NAMES = {n.strip().lower().rstrip(".") for n in os.environ.get(
    "OVERRIDE_NAMES", "admtecvozp2p.com.br,www.admtecvozp2p.com.br").split(",") if n.strip()}
UPSTREAM = (os.environ.get("UPSTREAM", "8.8.8.8"), 53)
ALLOW = [ipaddress.ip_network(c.strip(), strict=False) for c in os.environ.get("ALLOW", "").split(",") if c.strip()]
PORT = int(os.environ.get("DNS_PORT", "53"))

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


def handle(sock, q, addr):
    p = parse_question(q)
    if p is None:
        return
    name, qtype, _ = p
    if name in OVERRIDE_NAMES:
        sock.sendto(answer(q, NOERROR, OVERRIDE_IP if qtype == A else None), addr)   # AAAA etc: empty
        return
    if not allowed(addr[0]):
        sock.sendto(answer(q, REFUSED), addr)
        return
    up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    up.settimeout(3)
    try:
        up.sendto(q, UPSTREAM)
        sock.sendto(up.recv(4096), addr)
    except OSError:
        sock.sendto(answer(q, SERVFAIL), addr)
    finally:
        up.close()


def serve(port=PORT):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", port))
    print("DNS :%d  %s -> %s  forwarding for %s" % (port, sorted(OVERRIDE_NAMES), OVERRIDE_IP,
                                                   [str(n) for n in ALLOW] or "nobody"), flush=True)
    while True:
        q, addr = s.recvfrom(512)
        threading.Thread(target=handle, args=(s, q, addr), daemon=True).start()


if __name__ == "__main__":
    serve()
