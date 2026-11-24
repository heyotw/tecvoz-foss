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


if __name__ == "__main__":
    test_dns()
    print("ok")
