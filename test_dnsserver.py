"""Self-check for dnsserver.py against a fake local upstream: override, public forwarding,
UDP truncation + TCP fallback, ANY refused, per-IP rate limit, DNS over TLS."""
import os, socket, struct, threading, time

os.environ.update(OVERRIDE_IP="203.0.113.7", UPSTREAM="127.0.0.1", UPSTREAM_PORT="15454")
import dnsserver as d


def fake_upstream_reply(q):
    """Echo the query as a response; 'big.test' gets padded past the UDP limit."""
    pad = 700 if b"\x03big\x04test" in q else 0
    return q[:2] + b"\x81\x80" + q[4:] + b"\0" * pad


def fake_upstream():
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.bind(("127.0.0.1", 15454))
    t = socket.create_server(("127.0.0.1", 15454))

    def tcp():
        while True:
            c, _ = t.accept()
            q = d.recv_exact(c, struct.unpack(">H", d.recv_exact(c, 2))[0])
            r = fake_upstream_reply(q)
            c.sendall(struct.pack(">H", len(r)) + r)
            c.close()
    threading.Thread(target=tcp, daemon=True).start()
    while True:
        q, a = u.recvfrom(512)
        u.sendto(fake_upstream_reply(q), a)


def query(name, qtype):
    return struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + \
        b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0" + struct.pack(">HH", qtype, 1)


def udp(name, qtype, port=15353):
    c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    c.settimeout(2)
    c.sendto(query(name, qtype), ("127.0.0.1", port))
    r = c.recv(4096)
    flags, _qd, an = struct.unpack_from(">HHH", r, 2)
    return r, flags, an


def tcp(name, qtype, port=15353):
    q = query(name, qtype)
    with socket.create_connection(("127.0.0.1", port), timeout=2) as s:
        s.sendall(struct.pack(">H", len(q)) + q)
        return d.recv_exact(s, struct.unpack(">H", d.recv_exact(s, 2))[0])


def test_dns():
    threading.Thread(target=fake_upstream, daemon=True).start()
    threading.Thread(target=d.serve, args=(15353, "127.0.0.1"), daemon=True).start()
    time.sleep(0.3)
    r, flags, an = udp("WWW.admtecvozp2p.com.br", d.A)
    assert flags & 0xF == 0 and an == 1 and r[-4:] == socket.inet_aton("203.0.113.7") and r[:2] == b"\x12\x34"
    assert udp("admtecvozp2p.com.br", d.AAAA)[1:] == (0x8580, 0)        # empty NOERROR for AAAA
    r, flags, _ = udp("example.com", d.A)                                  # forwarded for anyone
    assert flags & 0xF == 0 and b"\x07example\x03com" in r
    r, flags, an = udp("big.test", d.A)                                    # too big for UDP
    assert flags & 0x0200 and an == 0 and len(r) <= d.UDP_MAX
    assert len(tcp("big.test", d.A)) > 700                                 # full answer over TCP 53
    assert udp("example.com", d.ANY)[1] & 0xF == d.REFUSED


def test_rate_limit():
    rl = d.RateLimit(rate=10, burst=5)
    assert all(rl.allow("1.2.3.4", now=0) for _ in range(5))
    assert not rl.allow("1.2.3.4", now=0)                # burst used up
    assert rl.allow("5.6.7.8", now=0)                    # other IPs unaffected
    assert rl.allow("1.2.3.4", now=0.2)                  # refills at 10/s


def test_dot():
    import ssl, subprocess, tempfile
    tmp = tempfile.mkdtemp()
    cert, key = os.path.join(tmp, "c.pem"), os.path.join(tmp, "k.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost",
                    "-keyout", key, "-out", cert], check=True, capture_output=True)
    threading.Thread(target=d.serve_dot, args=(cert, key, 18853), daemon=True).start()
    time.sleep(0.3)
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    q = query("www.admtecvozp2p.com.br", d.A)
    with ctx.wrap_socket(socket.create_connection(("127.0.0.1", 18853)), server_hostname="localhost") as s:
        for _ in range(2):                                     # two queries on one connection
            s.sendall(struct.pack(">H", len(q)) + q)
            r = d.recv_exact(s, struct.unpack(">H", d.recv_exact(s, 2))[0])
            assert r[:2] == b"\x12\x34" and r[-4:] == socket.inet_aton("203.0.113.7")


if __name__ == "__main__":
    test_dns()
    test_rate_limit()
    test_dot()
    print("ok")
