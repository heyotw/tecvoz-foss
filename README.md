# tecvoz-foss

Self-hosted replacement for the P2P (NAT traversal) server that TVT-based DVR/NVR viewer apps use to
reach a recorder by its serial number. The vendor's server went offline, so the app can no longer find
recorders remotely. This project re-implements that server from a protocol analysis ([NOTES.md](NOTES.md)).

- `natserver.py`: the P2P server (HTTP server list + the vendor's reliable-UDP + XML commands).
- `dnsserver.py`: small DNS server that points the vendor's hostname at your `natserver.py`.

Python 3.8+, standard library only. No vendor code, binaries or logos are included.

> **Status: work in progress.** The real app connects to `natserver.py`, completes the handshake and
> looks up a recorder. Recorder registration and the P2P/relay video connection are not implemented yet,
> so it does not stream video yet.

## Quick configuration

You need a Linux server with a public IP address (any small VM works) and the recorder's network settings.

### 1. Open the ports

| Port | Protocol | Used by |
|---|---|---|
| 80 | TCP | server list (`natserver.py`) |
| 8989 | UDP | P2P traffic (`natserver.py`) |
| 53 | UDP | DNS (`dnsserver.py`) |
| 853 | TCP | DNS over TLS for phones (`dnsserver.py`, optional) |

Google Cloud example:
```bash
gcloud compute firewall-rules create p2p-server --allow tcp:80,udp:8989,udp:53,tcp:853 --target-tags p2p-server
```
Then add the `p2p-server` network tag to the VM, and reserve a static external IP for it so the address
you configure on the recorder never changes.

### 2. Run the servers

Replace `SERVER_IP` with the server's public IP and `HOME_IP` with your home's public IP
(`curl ifconfig.me` from a computer at home).

```bash
sudo NAT_PUBLIC_IP=SERVER_IP python3 natserver.py
```

```bash
sudo OVERRIDE_IP=SERVER_IP ALLOW=HOME_IP python3 dnsserver.py
```

`dnsserver.py` answers the vendor hostname for anyone, and forwards other lookups to `8.8.8.8` only
for addresses in `ALLOW` (comma-separated IPs or CIDRs). Everyone else is refused, so it can't be abused
as an open resolver.

To keep them running after reboot, create `/etc/systemd/system/natserver.service`:
```ini
[Unit]
Description=P2P NAT server
After=network-online.target

[Service]
Environment=NAT_PUBLIC_IP=SERVER_IP
ExecStart=/usr/bin/python3 /opt/tecvoz-foss/natserver.py
Restart=always

[Install]
WantedBy=multi-user.target
```
Do the same for `dnsserver.py` (with `OVERRIDE_IP` and `ALLOW`), then
`sudo systemctl enable --now natserver dnsserver`.

### 3. Point the recorder at it

In the recorder's menu, open the network settings (TCP/IP), switch from DHCP to a manual/static
configuration if the DNS fields are locked, and set:

- Preferred DNS: `SERVER_IP`
- Alternate DNS: `8.8.8.8`

If the recorder seems to reach the vendor anyway (some embedded resolvers ask both DNS servers), set both
fields to `SERVER_IP`. The vendor hostname is answered for everyone; other lookups only work while your
home IP is in `ALLOW`.

### 4. Point the phone at it (DNS over TLS)

The app looks up the same hostname. Android's **Private DNS** setting works on Wi-Fi and mobile data, but
needs a hostname with a TLS certificate:

1. Create a DNS record at your domain: `p2p.example.org  A  SERVER_IP`.
2. Get a certificate. `natserver.py` answers Let's Encrypt challenges from `ACME_DIR`, so it can keep port 80:
   ```bash
   sudo mkdir -p /var/lib/acme && echo ACME_DIR=/var/lib/acme | sudo tee -a /etc/tecvoz-foss.env
   sudo systemctl restart natserver
   sudo certbot certonly --webroot -w /var/lib/acme -d p2p.example.org --deploy-hook "systemctl restart dnsserver"
   ```
3. Give the certificate to `dnsserver` with `/etc/systemd/system/dnsserver.service.d/dot.conf`:
   ```ini
   [Service]
   LoadCredential=dot.crt:/etc/letsencrypt/live/p2p.example.org/fullchain.pem
   LoadCredential=dot.key:/etc/letsencrypt/live/p2p.example.org/privkey.pem
   Environment=DOT_CERT=dot.crt DOT_KEY=dot.key
   ```
   then `sudo systemctl daemon-reload && sudo systemctl restart dnsserver` and open TCP 853.
4. On the phone: Settings, Network & internet, Private DNS, "Private DNS provider hostname":
   `p2p.example.org`.

DNS over TLS forwards lookups for any client (it runs over TCP, so it can't be used for amplification).

On iPhone, or without a domain, set the Wi-Fi DNS to `SERVER_IP` instead (home Wi-Fi only).

## Configuration reference

| Variable | Default | Meaning |
|---|---|---|
| `NAT_PUBLIC_IP` | `127.0.0.1` | IP `natserver.py` hands to apps and recorders |
| `NAT_PORT` | `8989` | UDP port for P2P traffic |
| `NAT_HTTP_PORT` | `80` | TCP port for the server list |
| `OVERRIDE_IP` | `127.0.0.1` | IP returned for the vendor hostname |
| `OVERRIDE_NAMES` | `admtecvozp2p.com.br,www.admtecvozp2p.com.br` | hostnames to redirect |
| `ALLOW` | empty | clients allowed to use DNS forwarding |
| `UPSTREAM` | `8.8.8.8` | DNS server for forwarded lookups |
| `DNS_PORT` | `53` | DNS port |
| `ACME_DIR` | empty | certbot `--webroot` directory served at `/.well-known/acme-challenge/` |
| `DOT_CERT`, `DOT_KEY` | empty | certificate and key for DNS over TLS (relative names are read from systemd credentials) |
| `DOT_PORT` | `853` | DNS-over-TLS port |
| `DNS_BIND` | `0.0.0.0` | address to bind; on systems where systemd-resolved holds `127.0.0.53:53`, use the NIC address (e.g. `10.128.0.4`) |

## Tests

```bash
python3 test_natserver.py && python3 test_dnsserver.py
```

## Legal

Independent project, not affiliated with or endorsed by Tecvoz or TVT. Product names are used only to
describe compatibility and belong to their owners. The protocol was analysed solely for interoperability
with hardware the author owns.
