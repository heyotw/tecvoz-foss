# Protocol notes

Reverse-engineered for interoperability: these notes describe how the stock viewer app (TW Viewer 1.5.7, a
rebranded TVT client) talks to its P2P / NAT traversal server, so `natserver.py` can stand in for the
vendor server that went offline. No vendor code or binaries are included in this repository.

## Background
- The app's P2P code is a native library (`libNatTraveral.so`, 32-bit ARM only). It still carries symbols and
  DWARF debug info, so the struct, field and enum names below are the original ones.
- The vendor host `www.admtecvozp2p.com.br` still resolves but stopped answering (seen 2026-11-24).
- The app's NAT server is chosen from a fixed built-in list (no free-text entry). A hidden settings menu
  appears when entering User `natsetting` / Password `haha123` on the Add Device screen.
- The Add Device screen silently does nothing unless the Nickname field is filled.

## 1. Server list (HTTP, TCP 80)
```
GET /NatServer/CNatServerList.xml?SN=<SN>&CT=AND&VER=1.5.7&APPID=AND%5FM%5FPH%5FTWViewer&APPUSERID=<32 hex>
Host: www.admtecvozp2p.com.br
```
Reply accepted by the app:
```xml
<ServerList><Item><Addr>IP</Addr><Port>8989</Port><TestPort>8990</TestPort></Item></ServerList>
```

## 2. Reliable UDP (`CNatUdt`)
24-byte little-endian header (`_udp_wrapper_head`):
```
category u8 | cmdId u8 (0 SYN, 1 DATA, 2 ACK, 3 RST) | optionEnable u8 (=1) | reserved u8 |
connectionID u32 | sendIndex u32 | recvIndex u32 | seqNum u32 | ackNum u32
```
- A peer only accepts packets whose `connectionID` equals its own initial sequence number
  (`IsMineDatagram`), so the server echoes the client's id in everything it sends.
- SYN payload is `fe fe 00 01` (protocolTag 0xfefe + version). Max payload 1476 bytes.
- Handshake: client `SYN(seq=C)` -> server `SYN(seq=S, ack=C)` -> client is connected; server data starts at S+1.
- ACK: `ackNum` = next expected seq - 1, optionally followed by u32 out-of-order seqs. Heartbeats are ACKs.
- Client sends `RST` when it is done or gives up.

## 3. Message framing (`CNatDataBlockParser`)
`u16 version (0x0100) | u16 options (bEncrypted bit) | i32 length` followed by an XML document (length <= 1023).

## 4. Commands
```xml
<Nat version="0.4.0.1"><Cmd id="N"> ...fields... </Cmd></Nat>
```
`NatTraversalCmdId` (reply id = request id + 10000):

| id | command | id | command |
|---|---|---|---|
| 1 | HEARTBEAT | 10004 | CLIENT_CONNECT_RELAY |
| 2 | DEVICE_UNREGISTER | 10005 | NOTIFY_CONNECT_RELAY |
| 10001 | DEVICE_REGISTER | 10006 | FETCH_DEVICE |
| 10002 | CLIENT_CONNECT_P2P | 10007 | DEVICE_MODIFY |
| 10003 | NOTIFY_CONNECT_P2P | | |

`TraversalReplyStatus`: 0 OK, 1 UNKNOWN, 2 DEVICE_OFFLINE, 3 DEVICE_REGISTERED, 4 SERVER_OVERLOAD,
5 DEVICE_NO_RELAY, 6 PEER_INVALID.

| command | request fields | reply fields |
|---|---|---|
| FETCH_DEVICE | RequestSeq, DeviceNo | RequestSeq, Status; if 0: DevicePeerIp (dotted), DevicePeerPort, CanRelay, [NatType], [UpnpPort], [ExtraInfo] |
| CLIENT_CONNECT_P2P | RequestSeq, DeviceNo, RequestPeerNat, P2PVersion, ConnectionId | RequestSeq, Status, DevicePeerIp, DevicePeerPort, DevicePeerNat, RefuseRelay, UpnpPort |
| CLIENT_CONNECT_RELAY | RequestSeq, DeviceNo | RequestSeq, Status, RelayServerIp, RelayServerPort, RelayConnectionId |

Recorder-side commands (DEVICE_REGISTER, NOTIFY_CONNECT_*) are not decoded yet; they need a capture from a
real recorder pointed at `natserver.py`.

## Status
- Verified against the real app: server list, UDP handshake, FETCH_DEVICE and an "offline" reply.
- To do: DEVICE_REGISTER, P2P hole punching (CLIENT/NOTIFY_CONNECT_P2P), relay.

## Test setup used
Android 11 in Docker (redroid) on an x86 cloud VM, with `libndk_translation` for 32-bit ARM
(ayasa520/redroid-script `-a 11.0.0 -n`). ARM cloud VMs (Ampere/T2A) cannot run 32-bit ARM code.
The container's traffic to the vendor IP was redirected to the test server with:
`iptables -t nat -I PREROUTING -s 172.17.0.0/16 -d 129.159.51.100 -j DNAT --to-destination 172.17.0.1`

## Tools
`tools/Decomp.java` (Ghidra headless: decompile functions by regex) and `tools/strs.py` (resolve
position-independent string references in that output; Ghidra image base 0x10000).
