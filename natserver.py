#!/usr/bin/env python3
"""Open replacement for the offline P2P / NAT traversal server used by TVT-based viewer apps (see NOTES.md).

Layers, all little-endian:
  1. HTTP  GET /NatServer/CNatServerList.xml  -> list of NAT servers (Addr/Port/TestPort)
  2. UDP   TVT reliable-UDP ("CNatUdt"): 24-byte header + payload
  3. Block 8-byte header (u16 version=0x0100, u16 options, i32 len) + XML command
"""
import os, random, socket, struct, threading
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

PUBLIC_IP = os.environ.get("NAT_PUBLIC_IP", "127.0.0.1")   # address handed to clients
NAT_PORT = int(os.environ.get("NAT_PORT", "8989"))
HTTP_PORT = int(os.environ.get("NAT_HTTP_PORT", "80"))

SYN, DATA, ACK, RST = 0, 1, 2, 3
HDR = struct.Struct("<BBBBIIIII")        # category cmd optionEnable reserved connId sendIdx recvIdx seq ack
SYN_TAG = b"\xfe\xfe\x00\x01"            # protocolTag 0xfefe, version 0x0100
BLK = struct.Struct("<HHi")

# NatTraversalCmdId: requests 1000x, replies 2000x (reply = request + 10000)
HEARTBEAT, DEVICE_UNREGISTER = 1, 2
DEVICE_REGISTER_REQ, CLIENT_CONNECT_P2P_REQ, NOTIFY_CONNECT_P2P_REQ = 10001, 10002, 10003
CLIENT_CONNECT_RELAY_REQ, NOTIFY_CONNECT_RELAY_REQ, FETCH_DEVICE_REQ, DEVICE_MODIFY_REQ = 10004, 10005, 10006, 10007
# TraversalReplyStatus
STATUS_OK, STATUS_UNKNOWN, STATUS_DEVICE_OFFLINE, STATUS_DEVICE_REGISTERED = 0, 1, 2, 3
STATUS_SERVER_OVERLOAD, STATUS_DEVICE_NO_RELAY, STATUS_PEER_INVALID = 4, 5, 6

DEVICES = {}   # SN -> Conn of a registered recorder (filled by DEVICE_REGISTER_REQ, next step)


def log(*a):
    print(*a, flush=True)


class Conn:
    """One client's reliable-UDP session (server side)."""

    def __init__(self, sock, addr, category, cid, peer_seq):
        self.sock, self.addr, self.cat, self.cid = sock, addr, category, cid
        self.seq = random.randrange(1, 0x7FFFFFFF)   # our initial sequence
        self.peer_seq = peer_seq                      # last in-order seq received
        self.send_idx = 0
        self.peer_idx = 0
        self.buf = b""                                # reassembled byte stream

    def raw(self, cmd, seq, ack, payload=b""):
        self.send_idx += 1
        self.sock.sendto(HDR.pack(self.cat, cmd, 1, 0, self.cid, self.send_idx, self.peer_idx, seq, ack) + payload, self.addr)

    def on_packet(self, cmd, send_idx, seq, payload):
        self.peer_idx = max(self.peer_idx, send_idx)
        if cmd == SYN:                                 # (re)transmitted SYN: answer SYN+ACK
            self.raw(SYN, self.seq, self.peer_seq, SYN_TAG)
        elif cmd == DATA:
            if seq == self.peer_seq + 1:               # ponytail: in-order only, client resends gaps
                self.peer_seq = seq
                self.buf += payload
                self.drain()
            self.raw(ACK, 0, self.peer_seq)
        elif cmd == RST:
            log("RST from", self.addr)

    def drain(self):
        while len(self.buf) >= BLK.size:
            ver, opts, n = BLK.unpack_from(self.buf)
            if len(self.buf) < BLK.size + n:
                return
            body, self.buf = self.buf[BLK.size:BLK.size + n], self.buf[BLK.size + n:]
            log("XML <-", self.addr, body.decode("utf-8", "replace"))
            self.on_xml(body)

    def send_xml(self, xml: bytes):
        self.seq += 1
        self.raw(DATA, self.seq, self.peer_seq, BLK.pack(0x0100, 0, len(xml)) + xml)
        log("XML ->", self.addr, xml.decode())

    def on_xml(self, body):
        try:
            cmd = ET.fromstring(body.rstrip(b"\0")).find("Cmd")
            cid = int(cmd.get("id"))
        except (ET.ParseError, AttributeError, TypeError, ValueError):
            log("bad XML from", self.addr)
            return
        f = {e.tag: (e.text or "") for e in cmd}
        reqseq = f.get("RequestSeq", "0")
        if cid == FETCH_DEVICE_REQ:
            dev = DEVICES.get(f.get("DeviceNo", "").upper())
            if dev is None:
                self.reply(FETCH_DEVICE_REQ + 10000, reqseq, STATUS_DEVICE_OFFLINE)
            else:
                ip, port = dev.addr
                self.reply(FETCH_DEVICE_REQ + 10000, reqseq, STATUS_OK, DevicePeerIp=ip,
                           DevicePeerPort=port, CanRelay=1)
        elif cid != HEARTBEAT:
            log("unhandled cmd", cid, f)

    def reply(self, cid, reqseq, status, **fields):
        x = '<Nat version="0.4.0.1"><Cmd id="%d"><RequestSeq>%s</RequestSeq><Status>%d</Status>' % (cid, escape(reqseq), status)
        x += "".join("<%s>%s</%s>" % (k, escape(str(v)), k) for k, v in fields.items())
        self.send_xml((x + "</Cmd></Nat>").encode())


def udp_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", NAT_PORT))
    conns = {}
    while True:
        d, addr = s.recvfrom(2048)
        if len(d) < HDR.size:
            continue
        cat, cmd, _opt, _res, cid, send_idx, _ridx, seq, ack = HDR.unpack_from(d)
        key = (addr, cid)
        c = conns.get(key)
        if cmd == SYN and c is None:
            if d[HDR.size:HDR.size + 2] != b"\xfe\xfe":
                continue
            c = conns[key] = Conn(s, addr, cat, cid, seq)
            log("SYN from", addr, "cid=%08x" % cid)
        if c:
            c.on_packet(cmd, send_idx, seq, d[HDR.size:])


SERVER_LIST = ('<?xml version="1.0" encoding="UTF-8"?>\n<ServerList><Item><Addr>%s</Addr>'
               '<Port>%d</Port><TestPort>%d</TestPort></Item></ServerList>')


def http_server():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", HTTP_PORT))
    s.listen(16)
    while True:
        c, a = s.accept()
        c.settimeout(5)
        req = b""
        try:
            while b"\r\n\r\n" not in req and len(req) < 8192:
                d = c.recv(4096)
                if not d:
                    break
                req += d
        except OSError:
            pass
        line = req.split(b"\r\n", 1)[0]
        log("HTTP", a, line.decode("latin-1"))
        if b"/NatServer/CNatServerList.xml" in line:
            body = (SERVER_LIST % (PUBLIC_IP, NAT_PORT, NAT_PORT + 1)).encode()
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body)
        else:
            c.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        c.close()


if __name__ == "__main__":
    threading.Thread(target=udp_server, daemon=True).start()
    log("NAT server: http :%d, udp :%d, advertising %s" % (HTTP_PORT, NAT_PORT, PUBLIC_IP))
    http_server()
