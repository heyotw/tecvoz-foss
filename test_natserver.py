"""Self-check: play the app's side (captured from TW Viewer 1.5.7) against natserver.py over UDP."""
import os, socket, struct, threading, time

os.environ["NAT_PORT"] = "18989"
import natserver as n


def test_fetch_unregistered_device_is_offline():
    threading.Thread(target=n.udp_server, daemon=True).start()
    time.sleep(0.2)
    c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    c.settimeout(2)
    srv = ("127.0.0.1", 18989)
    cid = 0x0EF6C10A

    # SYN exactly as the app sends it
    c.sendto(n.HDR.pack(2, n.SYN, 1, 0, cid, 0, 0, cid, 0) + n.SYN_TAG, srv)
    d = c.recv(2048)
    cat, cmd, _, _, rcid, _, _, sseq, ack = n.HDR.unpack_from(d)
    assert (cat, cmd, rcid, ack, d[n.HDR.size:]) == (2, n.SYN, cid, cid, n.SYN_TAG)

    xml = b'<Nat version="0.4.0.1"><Cmd id="10006"><RequestSeq>1</RequestSeq><DeviceNo>N00000000TST</DeviceNo></Cmd></Nat>\0'
    c.sendto(n.HDR.pack(2, n.DATA, 1, 0, cid, 1, 1, cid + 1, sseq) + n.BLK.pack(0x100, 0, len(xml)) + xml, srv)

    got = {}
    while not (n.DATA in got and n.ACK in got):
        d = c.recv(2048)
        h = n.HDR.unpack_from(d)
        got[h[1]] = (h, d[n.HDR.size:])
    assert got[n.ACK][0][8] == cid + 1                       # server acked our data
    (h, p) = got[n.DATA]
    assert h[4] == cid and h[7] == sseq + 1                  # client's id, next server seq
    ver, _, ln = n.BLK.unpack_from(p)
    body = p[n.BLK.size:n.BLK.size + ln]
    assert ver == 0x100
    assert b'<Cmd id="20006"><RequestSeq>1</RequestSeq><Status>2</Status>' in body, body


if __name__ == "__main__":
    test_fetch_unregistered_device_is_offline()
    print("ok")
