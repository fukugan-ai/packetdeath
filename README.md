# packetdeath

[日本語](README.ja.md) | English

packetdeath stops connections to ads and to known-bad sites with a watcher program that runs outside your browser.
The watcher compares the name of each destination with a list, and cuts only the connections whose names are on the list.

It is not a browser extension, so it does not rewrite anything inside the browser.
You can also point other devices in your home, such as an iPhone, at the same watcher.

## The problem

- Ads and trackers add a lot of traffic, and pages load slowly.
- Ad blockers that depend on browser extensions can stop working when the browser changes its rules.
- Setting up each device one by one is tedious.
- You would like fewer accidental connections to destinations that are publicly listed as bad.

packetdeath handles these with a list of destination names.
It lets through any connection whose name is not on the list, and any connection whose name it cannot read.
You can edit the lists while it runs.
An edit takes effect in about 0.3 seconds, with no restart.

## How it works

HTTPS (the encrypted traffic behind the padlock icon) hides the content of a connection.
At the very start of a connection, however, the name of the site you are connecting to is sent to the other side before encryption begins.
The watcher reads that name.
It does not read the content.

```
device ---(wants to connect to example.org)---> watcher ---name is on the list---> connection is cut
                                                   |
                                                   +---not on the list / unreadable---> let through
                                                   |
                                                   +---either way, one line per connection in flows.jsonl
```

In short, only names on the list are stopped, and everything else passes.

The watcher decides from three things.

- **SNI**: the name of the site, sent in plain text at the start of a connection.
- **CNAME**: an alias in a DNS answer (DNS is the system that turns names into addresses).
  An ad company sometimes hides behind an alias that looks like the site's own name.
- **Destination IP**: the address of the server.
  It helps with connections that carry no name, such as ones made straight to an IP address.

Two more terms.

- **blocklist**: the list of destinations to stop.
  Write one name per line.
  `example.org` matches `example.org` and `*.example.org`.
- **allowlist**: the list of destinations to always let through.
  It has the same format as a blocklist, and it is always checked before the blocklist.

There are three ways to put the watcher in place.

| Mode | Where the watcher sits | Admin rights | Where it has run |
|---|---|---|---|
| `proxy` | A relay (**proxy**). You point the proxy setting of a browser or an iPhone at it | Not needed | Linux |
| `block` | Uses a Linux kernel feature that hands traffic to a program (**nfqueue**). It sees traffic leaving the machine | Needed (root) | Linux |
| Windows service | Reads the capture left by the Windows built-in capture tool (**pktmon**) and cuts established connections | Needed | Windows 11 |

## What was checked, and the limits

The same commands as the quick start below were run on a Linux machine.

| Connection made | Result |
|---|---|
| `example.org`, which is on the list, through the watcher | `curl: (7) CONNECT tunnel failed, response 403`. The log line has `"decision":"block","reason":"sni"` |
| `example.com`, which is not on the list, through the same watcher | HTTP status `200`. The log line has `"decision":"pass"` |

This shows only that the mechanism works.
How many ads it removes, or how many bad sites it keeps out, depends on the quality of your lists, and this result cannot tell you.

It cannot stop connections whose names it cannot see.

- **ECH**: a newer feature that encrypts even the name of the site.
  When it is in use, the watcher cannot see the name.
- **QUIC** (UDP port 443 traffic) is counted and logged, but not stopped.
- Ads stitched into a video stream, ads served under the site's own name, and evasion of anti-ad-blocker scripts are out of scope.
- It cannot recognize DNS traffic from apps that look up names over HTTPS (**DoH**).

The project does not claim to prevent malware.
What it can stop is what is on a list, plus what an inspection tool (Suricata or ClamAV) flags.
The detection rate depends on the quality of the lists and of those tools.

## Who it suits, and who it does not

| | Suits | Does not suit |
|---|---|---|
| Ownership | Devices you manage, and devices inside your own home | Sending other people's traffic through it without their consent; placing it on a router |
| Goal | Stopping by a list of destination names and keeping a log of what was stopped | Removing ads by reading page content, or hiding page elements |
| Operation | Running from commands and config files | Operating from a screen (there is no UI) |
| OS | Linux, WSL, Windows 11 | macOS (it has not been run there) |

Before you use it, check a few points yourself.
The treatment of ad-blocking software differs by country and by situation.
The design document also lists legal questions that remain unconfirmed.
Check, site by site, whether a site's terms of service forbid blocking, as video sites may.

## Requirements

| Mode | You need |
|---|---|
| All | Rust (`cargo`), installed with [rustup](https://rustup.rs) |
| `proxy` | No admin rights |
| `block` | root and `iptables`, and a Linux kernel with nfqueue |
| Windows service | Admin rights and pktmon. The only way of producing the Windows executable that has been checked is cross building from Linux with `cargo build --release --target x86_64-pc-windows-gnu` |
| Inspection (optional) | ClamAV's `clamd`, used to inspect downloads over HTTPS |

## Quick start

These steps change no OS setting.
The watcher listens only on `127.0.0.1` (inside this machine).
Traffic goes through it only when you give `curl` the `-x` option.

1. Install Rust.
   You are done when `cargo --version` prints a version.
2. Fetch the repository and build it.

   ```
   git clone <URL of this repository>
   cd packetdeath
   cargo build --release
   ```

   The executable is `target/release/packetdeath`.

3. Create a working folder and a list of destinations to stop.

   ```
   mkdir -p pdtrial/log
   printf 'example.org\n' > pdtrial/blocklist.txt
   ```

4. Start the watcher.
   It prints a startup line and keeps waiting.

   ```
   ./target/release/packetdeath proxy --listen 127.0.0.1:8899 --blocklist pdtrial/blocklist.txt --deny 403 --log-dir pdtrial/log
   ```

5. In another terminal window, connect to the destination on the list.
   The connection is cut with a `403`.

   ```
   curl -sS -x http://127.0.0.1:8899 https://example.org/
   ```

   The output is `curl: (7) CONNECT tunnel failed, response 403` (the wording depends on your curl version).

6. Connect to a destination that is not on the list.
   It passes with a `200`.

   ```
   curl -sS -o /dev/null -w '%{http_code}\n' -x http://127.0.0.1:8899 https://example.com/
   ```

7. Read the log.

   ```
   tail -2 pdtrial/log/flows.jsonl
   ```

   The `example.org` line has `"decision":"block"` and `"reason":"sni"`, and the `example.com` line has `"decision":"pass"`.

8. Press `Ctrl+C` in the watcher's window to stop it.
   Remove the working folder with `rm -r pdtrial`, and everything is back as it was.

The language of the startup lines follows the environment variables `LC_ALL` and `LANG`: Japanese when the value starts with `ja`, English otherwise.
If you leave out `--deny 403` in step 4, a blocked connection pretends to succeed and then goes silent (**blackhole**).
In that mode, `curl` with `--max-time 5` ends after 5 seconds with `exit=28`.

## Using it day to day

- Point your browser's proxy setting at `127.0.0.1:8899` yourself.
  packetdeath does not touch the proxy settings of the machine it runs on, or the store of trusted certificates.
- To use it from another device in your home, give `--listen` the LAN IP address of this machine (for example `192.0.2.10:8899`).
  By default it accepts only `127.0.0.1` and the private home ranges (10.x, 172.16 to 172.31, 192.168.x).
  Add `--allow-from <CIDR>` to widen that.
- On an iPhone or a Windows PC, enter the automatic proxy configuration URL `http://192.0.2.10:8899/proxy.pac`.
  It keeps destinations inside your LAN out of the relay.
  If the watcher stops, traffic falls back to `DIRECT` (a direct connection).
- You can convert an EasyList file (the list format that ad blockers use) into a blocklist.
  `./target/release/packetdeath filterlist --in <EasyList file> --out <blocklist file>` only converts; it does not download anything.
  Get EasyList yourself (this repository does not ship it).
- When a legitimate site gets stopped, add its name to the allowlist, one line.
  No restart is needed.

Here is a start-up line that passes an allowlist.

```
./target/release/packetdeath proxy --listen 127.0.0.1:8899 --blocklist pdtrial/blocklist.txt --allowlist pdtrial/allowlist.txt --deny 403 --log-dir pdtrial/log
```

The lists that ship with the repository:

| File | Contents | Source |
|---|---|---|
| `blocklists/telemetry-windows.txt` | Six destinations for Windows and Office diagnostic data | A short list picked from a real machine's log |
| `allowlists/microsoft-required.txt` | Destinations Microsoft publishes as required for its services | Converted from Microsoft's public API |
| `allowlists/pihole-common.txt` | The widely used Pi-hole "do not block" destinations | Converted from `anudeepND/whitelist` (the license follows the original; NOT VERIFIED, check the original's notice) |
| `allowlists/user-named.txt` | Destinations a user asked for by name | Written by hand |

## Details

| You want to | Use |
|---|---|
| Only log, without stopping anything | `packetdeath observe` (Linux) |
| Stop traffic leaving a Linux machine | `packetdeath block` (root) |
| Relay and stop the traffic of other devices | `packetdeath proxy` |
| Keep it running on Windows | `packetdeath service-install` and `packetdeath service-uninstall` |
| Measure the stop rate and the wrongly-stopped rate | `packetdeath eval --labels <tsv>` |
| Replay a new list against past logs to estimate false hits | `packetdeath defense-report --flows <flows.jsonl> --blocklist <list>` |
| Build lists of bad destinations from public feeds | `scripts/pd-malware-feed.sh` (next section) |

Run `packetdeath` with no arguments to see the usage of every command.

Choose where logs go with `--log-dir`.

- `flows.jsonl`: one line per connection.
  It holds the time, the source and destination IP and port, the SNI, and the decision.
- `dns.jsonl`: DNS answers, when you pass `--dns`.
- `watch.jsonl`: hits of the watch-only options.

The logs contain every destination the device connected to.
Treat them as secret and do not share them.
packetdeath does not send logs anywhere.

### Inspecting the content of connections (optional)

Only when you give all three of `--mitm-list`, `--ca-dir` and `--clamd`, packetdeath decrypts HTTPS and inspects downloads, and only for the destinations in `--mitm-list`.
Decryption needs you to make the device trust a certificate of the certificate authority (**CA**) that packetdeath created.
packetdeath does not install that certificate on any device.

Anyone who can read `ca.key` (the CA's private key) can impersonate any site to a device that trusts the certificate.
Keep `ca.key` outside the repository, with mode `0600`.
Do not put destinations of apps that pin certificates, such as banking apps and password managers, in `--mitm-list`.
The procedure is in `docs/mitm-runbook.md` and in the "段階8 MITM" section of `docs/design.md` (both in Japanese).

### Stopping distrusted certificates (optional)

There are options that stop connections to sites presenting certificates that a browser vendor or similar source has announced as untrustworthy.
Start with `--watch-distrust`, which only records.
Move to `--distrust` after you have looked at the result of `defense-report --watch`.
The details are in the "段階10 能動防御" section of `docs/design.md` (in Japanese).

## Importing outside lists

`scripts/pd-malware-feed.sh --out <output folder> [--auth <key file>]` fetches public lists and converts them into the form packetdeath reads.
packetdeath itself never starts this script or fetches any list.
It runs with `curl` and `sh`.

| List | Key | Terms |
|---|---|---|
| Feodo Tracker (IPs of malicious servers) | Not needed | CC0 (free for anyone to use, commercial use included) |
| SSL Blacklist | Not needed | CC0 |
| ThreatFox | Needed | Provided by abuse.ch only to authenticated users |
| URLhaus | Needed | Provided by abuse.ch only to authenticated users |
| OneCRL (Mozilla's list of revoked certificates) | Not needed | Follows the publisher's terms |

ThreatFox and URLhaus need an abuse.ch authentication key.
Put the key in a file written as a curl configuration, set its mode to `0600`, and pass it with `--auth`.
If the key file is missing or its mode is too loose, the script sends no request at all to these two feeds.
It prints a `[warn]` and keeps the previous lists.
It chooses stale lists over breaking the terms.

Publishers can change their terms.
Read each publisher's terms before you import.
The repository does not contain the contents of any list.

An example setup for a daily fetch is in `scripts/systemd/pd-malware-feed.service` and `pd-malware-feed.timer`.
A person runs the commands that install it.

## Safety and how to undo

### When the watcher stops

| Mode | Traffic when it stops |
|---|---|
| `block` (Linux) | Passes untouched, but only when the rule carries `--queue-bypass`; if you leave it out, all matching traffic stops while the watcher is absent |
| Windows service | Passes untouched (the watcher is not in the path of the traffic) |
| `proxy` | Clients can no longer reach the relay. Remove the proxy setting, or use the automatic configuration (proxy.pac), and traffic falls back to `DIRECT` |

Traffic it cannot decide about (a name it cannot read, a handshake it cannot reassemble) passes in every mode.

### Undoing part of it

| What happened | How to undo | Takes effect in |
|---|---|---|
| One legitimate site was stopped | Add its name to the allowlist, one line | About 0.3 seconds |
| Blocking by the distrusted-certificate lists stops too much traffic | Create the file you gave to `--defense-off <path>` (`touch <path>`). Delete it to restore | About 0.3 seconds |
| One list stops many destinations at once | A safety valve (breaker) automatically drops that list to watch-only | The next decision after a hit |
| You want everything to stop | Stop the watcher process | Immediately |

While the `--defense-off` file exists, only blocking by the distrusted-certificate lists and by the chain check (`--probe-chains`) is switched off.
Those hits are written to `watch.jsonl` instead of being stopped.
The ad blocklist and the allowlist behave as before.

### Using `block` on Linux

You add the rules, and you remove them.
packetdeath never runs `iptables` itself.
This avoids leaving rules behind if the watcher dies.

Add (send TCP port 443 to the watcher):

```
sudo iptables -I OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num 1808 --queue-bypass
sudo ./target/release/packetdeath block --queue 1808 --blocklist <blocklist file> --log-dir <log folder>
```

Under `sudo`, `$HOME` changes, so always pass `--log-dir`.

Remove (change `-I` to `-D` in the rule you added, with the same arguments):

```
sudo iptables -D OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num 1808 --queue-bypass
sudo iptables -S | grep -c 1808
```

If the second command prints `0`, no rule is left.
These rule steps are in the design document (PK-1 to PK-4 in `docs/design.md`).
The `block` rules were not run again when this README was written (NOT VERIFIED).

### Using it on Windows

If you forget to stop a pktmon capture, the capture file grows without limit.
Confirm the cleanup first, then start.

```
pktmon stop
pktmon filter remove
pktmon status
```

Delete the captured files (`.etl` and the converted `.pcapng`).
They contain every destination the device connected to.
The exact output of these commands is also unconfirmed in the design document, so check it the first time you run them (NOT VERIFIED).

To remove the Windows service, run `packetdeath service-uninstall`.
The service installs no extra driver.
Automatic start after a reboot has not been tested on a real run (NOT VERIFIED).

### Logs and keys

- The logs (`flows.jsonl`, `dns.jsonl`, `av.jsonl`) contain the destinations the device connected to.
  Treat them as secret.
- Never put the CA private key (`ca.key`) in the repository (`.gitignore` excludes `*.key` and `*.crt`).
- Apart from relaying your traffic, packetdeath and its bundled script open only two kinds of connections to the outside.
  One is the list-fetching script's traffic.
  The other is the check connection the watcher opens when you pass `--probe-chains`, which sends the destination's name.

## Documents

- `docs/design.md`: the design and the acceptance IDs (in Japanese).
  It states what to measure for a pass, with commands and expected output.
- `docs/mitm-runbook.md`: the operating procedure for content inspection (in Japanese).
- `blocklists/README.md`: where the bundled blocklist came from, and what must never be added to it.
- `allowlists/README.md`: where the bundled allowlists came from, and their counts.

## License

The package declares `MIT OR Apache-2.0` in `Cargo.toml`.
Suricata and ClamAV are GPLv2; packetdeath uses them as separate processes and does not link to them.
`scripts/clamav-2g.patch` and `scripts/clamav-64/` are patches to ClamAV's source.
These two follow ClamAV's license (GPLv2), and the `MIT OR Apache-2.0` of the package does not extend to them.
The license of each bundled list follows its source (see the table above).
