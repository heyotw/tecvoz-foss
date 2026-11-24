"""Self-check for dnsserver.py: override answers, AAAA empty, non-allowed clients refused."""
import os, socket, struct, threading, time

os.environ.update(OVERRIDE_IP="203.0.113.7", ALLOW="10.9.9.9/32")
import dnsserver as d


def query(name, qtype, port):
    q = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0" + struct.pack(">HH", qtype, 1)
    c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    c.settimeout(2)
    c.sendto(q, ("127.0.0.1", port))
    r = c.recv(512)
    flags, qd, an = struct.unpack_from(">HHH", r, 2)
    return r, flags & 0xF, an


def test_dns():
    threading.Thread(target=d.serve, args=(15353,), daemon=True).start()
    time.sleep(0.2)
    r, rcode, an = query("WWW.admtecvozp2p.com.br", d.A, 15353)
    assert (rcode, an) == (0, 1) and r[-4:] == socket.inet_aton("203.0.113.7")
    assert r[:2] == b"\x12\x34"
    assert query("admtecvozp2p.com.br", d.AAAA, 15353)[1:] == (0, 0)
    assert query("example.com", d.A, 15353)[1] == d.REFUSED     # 127.0.0.1 is not in ALLOW


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
    q = struct.pack(">HHHHHH", 0xBEEF, 0x0100, 1, 0, 0, 0) + b"\x03www\x0cadmtecvozp2p\x03com\x02br\x00" + struct.pack(">HH", d.A, 1)
    with ctx.wrap_socket(socket.create_connection(("127.0.0.1", 18853)), server_hostname="localhost") as s:
        for _ in range(2):                                     # two queries on one connection
            s.sendall(struct.pack(">H", len(q)) + q)
            r = d.recv_exact(s, struct.unpack(">H", d.recv_exact(s, 2))[0])
            assert r[:2] == b"\xbe\xef" and r[-4:] == socket.inet_aton("203.0.113.7")


if __name__ == "__main__":
    test_dns()
    test_dot()
    print("ok")
