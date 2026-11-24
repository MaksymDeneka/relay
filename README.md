# Relay

Routes chosen devices on the home network (iPhones, for example) through SOCKS5 or HTTP
proxies, with a web dashboard to pick and switch the proxy for each device.

Only devices you add are affected. A phone joins by setting this Mac as its Wi-Fi router and
DNS server; every other device on the network keeps using the normal router.

## How it works

```
iPhone ──(router = this Mac)──▶ pf rdr ──▶ sing-box ──▶ SOCKS5/HTTP proxy ──▶ internet
```

- **pf** (the macOS firewall) loads rules into the anchor `com.apple/relay`; `/etc/pf.conf`
  is not edited. For listed device IPs only, it redirects outbound TCP to sing-box's
  `redirect` listener and DNS to sing-box's DNS listener. All other traffic those devices send
  to the internet (UDP, ICMP) is dropped, so nothing bypasses the proxy.
- **sing-box** answers DNS with fake IPs (198.18.0.0/15), so each proxy receives the real
  domain name and resolves it on its side. Every device has its own selector, so switching one
  device between existing proxies, Direct and Block takes effect immediately and doesn't drop
  other devices' connections. Adding or removing a device or a proxy restarts sing-box, so
  every device reconnects once. That includes **new proxy**, and moving a device off a session
  **new proxy** made (the session is removed then).
- Relay doesn't need or enable IP forwarding, and the Mac's own traffic is never touched.
- Modes per device: **Proxy** (chosen proxy), **Direct** (this Mac's own connection),
  **Block** (no internet). If a device's proxy is deleted, the device is blocked, not leaked.
  Direct mode resolves names on the Mac and refuses loopback and tailnet addresses, so a device
  can't reach services that only listen on this Mac. It is a selector choice like a proxy (a
  hop through a loopback SOCKS listener, port 17891, where that check runs), so switching any
  device between Proxy, Direct and Block normally takes effect without restarting sing-box.
  The exception is leaving a session **new proxy** made: the session is removed, which restarts
  sing-box.
- DNS from devices gets fake-IP answers for A records only; other query types are refused.
- When the service stops, the anchor keeps only the block rules, so devices that still use this
  Mac as their router get no internet instead of being forwarded unproxied (macOS may have IP
  forwarding on for other reasons). `scripts/uninstall.sh` removes the rules and releases
  Relay's pf enable reference.
- While any device is configured, the service holds a `caffeinate -i` assertion so the Mac
  doesn't idle-sleep. If the Mac is off, the listed phones have no internet until they switch
  back to Automatic.

## Install

```sh
brew install sing-box
sudo scripts/install.sh            # or: sudo scripts/install.sh /path/to/node
```

This installs the launchd daemon `local.relay.gateway`, which runs `server.mjs` as root
(pf and the redirect listener need it), starts at boot and restarts if it crashes.

## Dashboard access

The dashboard listens on loopback only, never on the LAN; Tailscale is the way in.

| From | URL | Sign-in |
|---|---|---|
| Your Mac (tailnet) | `https://<mac>.<tailnet>.ts.net:8787` | none: Tailscale Serve sends `Tailscale-User-Login`, which must be the owner |
| Phones (Funnel) | `https://<mac>.<tailnet>.ts.net:10000` | a password, then a signed `__Host-` cookie for 30 days |
| This Mac, only without `access.json` and with `RELAY_LOCAL_DASHBOARD=1` | `http://localhost:8787` | none |

Create `data/access.json`:

```json
{
  "tailnet": { "host": "<mac>.<tailnet>.ts.net:8787", "allowedLogin": "you@example.com" },
  "public": {
    "origin": "https://<mac>.<tailnet>.ts.net:10000",
    "port": 8789,
    "passwordFile": "/path/to/password.json",
    "username": "relay"
  },
  "directPorts": [8443]
}
```

`passwordFile` is a JSON file with `passwordSalt` and `passwordHash`
(`scrypt(password, salt, 32)` as hex). It is read on every sign-in, so another dashboard on
the same Mac can share it. `username` is the hidden username on the sign-in form; set it to
the one another dashboard on the same host uses, and password managers offer the saved
password for both. Sign-ins are capped at 5 per minute. To sign out every phone, delete
`settings.sessionSecret` from `data/state.json` and restart the service.

Without `access.json`, the dashboard refuses every request unless Relay was started with
`RELAY_LOCAL_DASHBOARD=1`; then `http://localhost:8787` works without a sign-in, but never for
requests forwarded by a proxy such as Tailscale Serve. Once the file exists, its `tailnet`
block is required. With it, every request on port 8787
needs the Tailscale owner identity, including ones with a `localhost` Host header (Serve passes
the client's Host through). If `access.json` can't be read or is incomplete (for example a
`tailnet` entry without `allowedLogin`), the dashboard refuses every request until it is fixed.

Make a password file:

```sh
node -e 'const c=require("crypto"),s=c.randomBytes(16).toString("hex");console.log(JSON.stringify({passwordSalt:s,passwordHash:c.scryptSync(process.argv[1],s,32).toString("hex")}))' 'your password' > data/password.json
chmod 600 data/password.json
```

Expose it with Tailscale:

```sh
tailscale serve --bg --https=8787 http://127.0.0.1:8787      # tailnet only
tailscale funnel --bg --https=10000 http://127.0.0.1:8789    # public, password protected
tailscale funnel --https=10000 off                           # stop phone access from the internet
```

Routed devices reach the Mac's own Tailscale name directly, not through their proxy, on the
phone sign-in port and any `directPorts` (for example another password-protected dashboard), so
those still open on a phone that is blocked or whose proxy only allows ports 80 and 443.

```sh
sudo scripts/uninstall.sh          # stop and remove the service (data/ is kept)
sudo launchctl kickstart -k system/local.relay.gateway   # restart after code changes
tail -f data/relay.log
```

The service also re-applies the rules every 20 seconds, in case pf is reset or the Mac's LAN
address changes.

## Connect a phone

1. Dashboard → **Add device**: a name and a fixed IP outside the router's DHCP range (e.g.
   `192.168.0.201`). Pick a proxy.
2. iPhone → Settings → Wi-Fi → ⓘ → **Configure IP → Manual**: that IP, subnet mask
   `255.255.255.0`, **Router** = the Mac's IP (the dashboard shows it).
3. **Configure DNS → Manual**: only the Mac's IP.
4. Turn off **Limit IP Address Tracking** (same screen) and **iCloud Private Relay**.
5. To leave, set Configure IP and DNS back to Automatic.

The device card shows "online" once traffic flows. **Check exit IP** looks up the address the
proxy exits from.

## Proxies

**Import** accepts one proxy per line, in any of these forms:

```
host:port:user:pass
user:pass@host:port
socks5://user:pass@host:port
http://user:pass@host:port
185	socks	host:port:user:pass	provider      (rows copied from a spreadsheet)
```

Labels come from `sid-NNN` in the username, and the flag from `country-xx`. **Check** looks up
each proxy's exit IP, location and latency through the proxy itself (HTTPS to ipinfo.io on port
443, which proxies limited to web ports allow).

**new proxy** under a device's route gives it a fresh exit IP in one tap. Relay copies the
device's proxy (or the first proxy with a numeric `sid-NNN` in its username) with a new random
session number, checks it, and switches the device only if it works and exits on an IP no listed device
uses. Sessions made this way are removed once no device uses them; imported proxies stay.
Adding the new session restarts sing-box, so every phone reconnects once. If you change the
device's route while the new session is being checked, your change wins.
Without any `sid-` proxy, the link is **next proxy** instead: the next proxy in the list that no
other device uses and that hasn't failed its last check.

## IPv6

Relay routes IPv4 only. If the router hands out public IPv6, listed phones can reach the
internet over IPv6 straight through the router, around the proxy. The dashboard shows a red
warning when this Mac sees a public IPv6 prefix on the LAN, or when a listed phone has a public
IPv6 address (matched by MAC through the ARP and NDP tables). Only interfaces that serve listed
devices count. Local-only IPv6 (`fd…` addresses,
for example from a HomePod or Apple TV acting as a Thread border router) is ignored. The fix is
to turn IPv6 off on the router.

## Limits

- TCP only. UDP from routed devices is dropped, so QUIC falls back to TCP. Voice and video
  calls that need UDP won't work while a phone is on the relay.
- IPv4 only. DNS returns no AAAA records, so apps use IPv4.
- Devices are identified by IP, so give each one a fixed address.
- The root daemon runs `server.mjs`, `node` and `sing-box` from where they were installed (the
  checkout, nvm, Homebrew), which your user account can modify. Copying them to root-owned
  paths would close that gap; it isn't done yet.
- Many residential proxies only connect to ports 80 and 443. Apps that use other ports fail
  while they go through one of those.

## Files

- `server.mjs`: HTTP server and API
- `lib/gateway.mjs`: keeps sing-box, pf and caffeinate in line with the saved state
- `lib/singbox.mjs`: sing-box config builder and process supervisor
- `lib/pf.mjs`: pf anchor rules
- `lib/check.mjs`: SOCKS5/HTTP exit-IP check
- `lib/proxies.mjs`: import parser
- `public/`: dashboard (no build step, no dependencies)
- `data/`: `state.json` (proxies, devices, password hash; mode 600), runtime config and log

Tests: `npm test`.
