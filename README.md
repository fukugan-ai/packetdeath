# packetdeath

[日本語](README.ja.md) | English

packetdeath stops connections to ads and to known-bad sites with a watcher program that runs outside your browser.
The watcher compares the name of each destination with a list, and cuts only the connections whose names are on the list.

It is not a browser extension, so it does not rewrite anything inside the browser.
You can also point other devices in your home, such as an iPhone, at the same watcher.

## What it can do (10 stages)

packetdeath is built in stages.
The stage numbers are the same as the "段階" (stage) numbers in `docs/design.md`.
Every stage works only when you pass its options.

| Stage | What it does | Options |
|---|---|---|
| 1 Observe | Records destinations without stopping anything (the Windows version is 1w and reads a pktmon capture) | `observe`; on Windows, `--pcapng` (an option of `block` and `service-install`) |
| 2 Block | Cuts connections to destination names on a list; names on the allowlist always pass | `--blocklist` `--allowlist` |
| 3 CNAME | Cuts connections whose DNS alias points to a listed name (Linux `block`; `proxy` does not accept it) | `--dns` |
| 4 IDS/IPS | Reads the alerts of the detection tool Suricata and cuts destinations that raised a severe alert (Linux `block`) | `--eve` `--ips-severity` `--ips-sids` `--ips-ttl` |
| 5 Destination IP | Cuts listed addresses (IPs), including connections that carry no name | `--iplist` |
| 6 Read outside scan results | Reads the "malicious" verdicts that an outside scanner wrote to `av.jsonl` and cuts those destinations (`block` and `proxy`). Passing the `av.jsonl` of stage 8 is not the default setup, because it would also catch other sites that share a CDN IP | `--av` |
| 7 Proxy | Relays the traffic of other devices and applies the blocklist and allowlist of stage 2, the iplist of stage 5 and the `--av` of stage 6 (it does not accept `--dns`, `--eve` or `--ips-*`) | `proxy --listen` `--deny` |
| 8 MITM and antivirus | For destinations you name, opens encrypted traffic and inspects downloaded files with ClamAV | `--mitm-list` `--ca-dir` `--clamd` |
| 9 Malware feeds | Imports public lists of bad destinations daily and cuts them with the blocklist of stage 2 and the iplist of stage 5 | `scripts/pd-malware-feed.sh`; `--blocklist` and `--iplist` (repeatable) |
| 10 Active defense | Cuts destinations whose certificate chain has been announced as untrustworthy; the blocking side can be put back to watch-only with one action | `--distrust` `--watch-distrust` `--probe-chains` `--defense-off` `--breaker-hosts` |

Stages 4 to 10 are explained in "Details" and "Active defense".
Stage 4 uses Suricata, and stage 8 uses ClamAV and a certificate that you install.
Suricata and ClamAV are separate tools; this repository does not include them.

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
| IDS/IPS (optional) | Suricata (installed separately; used with Linux `block`) |
| Inspection (optional) | ClamAV's `clamd`, used to inspect downloads over HTTPS, and the packetdeath certificate installed on the device |

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
| `blocklists/telemetry-windows.txt` | Five destinations for Windows and Office diagnostic data | A short list picked from a real machine's log |
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

### Detecting and stopping intrusions (IDS/IPS)

An **IDS** (intrusion detection system) finds suspicious traffic and reports it.
An **IPS** (intrusion prevention system) stops the traffic it finds.
packetdeath has no rules of its own for recognizing suspicious traffic.
The detection tool **Suricata**, which does have rules, writes alerts to a file called `eve.json`, and packetdeath's `block` reads those alerts and stops the destinations.

You install Suricata separately.
packetdeath does not start Suricata.
Run Suricata in detection-only mode (IDS mode); packetdeath does the stopping.
For installation and startup, follow the Suricata documentation (<https://docs.suricata.io/>).

You choose which alerts to act on with one of two options.

- `--ips-severity <N>`: act on alerts whose severity (`alert.severity`, 1 to 3, where 1 is the most severe) is N or lower.
- `--ips-sids <file>`: a file with one rule number (sid) per line; act on alerts for the listed numbers.

If you pass both, an alert that matches either one is acted on.
If you pass neither, nothing is stopped because of an alert.
`--eve <path>` gives the location of `eve.json`.
A stopped destination stays stopped for `--ips-ttl <seconds>` (default 300).

```
sudo iptables -I OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num 1808 --queue-bypass
sudo ./target/release/packetdeath block --queue 1808 --eve <location of eve.json> --ips-severity 1 --log-dir <log folder>
```

This mechanism has four limits.

- An alert is written after the traffic has passed, so the packet that raised the alert gets through, and what stops is later traffic to the same destination.
- Only traffic that an iptables rule sends to the watcher can be stopped (the example above covers TCP port 80).
- The severity comes from the classification (classtype) of the Suricata rule. In the measurement recorded in the design document, all 30 alerts on one machine were internal notices of severity 3, so `--ips-severity 1` stopped none of them.
- The detection rate depends on the quality of the Suricata rules, so the project cannot say that it prevents malware.

If Suricata stops, traffic keeps flowing; alerts just stop arriving.
This stage is an option of Linux `block`.
How to use Suricata on Windows is unconfirmed in the design document (NOT VERIFIED).

### Opening encrypted traffic (MITM)

**MITM** (man in the middle) means that the relay decrypts traffic midway, looks at the content, and encrypts it again before passing it on.
Misused, it is eavesdropping, so packetdeath does it only after you install the packetdeath certificate on your own device and allow it.

Only when you give all three of `--mitm-list`, `--ca-dir` and `--clamd` does packetdeath open encrypted traffic (HTTPS), and only for the destinations in `--mitm-list`.
If you give only one or two, it starts with opening disabled and prints the missing option names as a `[warn]`.
On Windows it ignores all three and prints a `[warn]`.

In the opened traffic it looks only at downloaded files.
A connection is opened only when all six of these hold.

1. All three options are given and the CA (the certificate issuer) can be read.
2. The connection did not match the blocking rules (blocklist, iplist, av).
3. The destination is not on the allowlist.
4. The destination is on `--mitm-list`.
5. The destination port is 443 and the connection was not made to a bare IP address.
6. The pair of device and destination is not one that packetdeath stopped opening and remembers for one hour (see "What happens without the certificate").

#### What happens without the certificate

When a device without the certificate connects to a destination on `--mitm-list`, the browser shows a certificate warning and the first connection fails.
packetdeath remembers that pair of device and destination for one hour and, from the next connection, passes the traffic without opening it.
Destinations that are not on the list are passed without opening, as before, whether or not the device has the certificate.

#### Why the certificate is dangerous

packetdeath does not install this certificate on any device.
You install it yourself.

Anyone who can read `ca.key` (the CA's private key) can impersonate any site to a device that has installed the certificate.
In other words, if `ca.key` leaks, the encrypted traffic of that device can be opened.
Keep `ca.key` outside the repository, with mode `0600`.
The CA is valid for 730 days.

Do not put destinations of apps that pin certificates in `--mitm-list`, such as banking apps, password managers, Apple services, Microsoft sign-in, and Windows Update.
Opening them breaks those apps.
When in doubt, leave a destination out.

#### Installing and removing the certificate

A proxy started with all three options serves the certificate `ca.crt` at `http://<proxy IP>:<port>/ca.crt`.
It never serves `ca.key`.

- Windows (current user only): run `certutil -user -addstore Root "<path>\ca.crt"` on the saved `ca.crt`.
  To remove it, open `certmgr.msc` and delete `packetdeath CA <date>` under "Trusted Root Certification Authorities".
- iPhone: open the URL above in Safari, install the profile, and turn it on under "Certificate Trust Settings".
  To remove it, delete the profile under "VPN & Device Management" in Settings.
  The wording of these screens comes from memory in the design document, so check it the first time you do this (NOT VERIFIED).
- Firefox keeps its own trust store and is out of scope.

If `ca.key` leaks, do this in order:

1. Remove the old certificate from every device.
2. Stop the proxy.
3. Delete the contents of `--ca-dir`.
4. Start the proxy.
   A new CA is created and the startup log shows its new fingerprint.
5. Install the new `ca.crt` on every device again.

During steps 1 to 5, opening fails and traffic falls back to uninspected passing; traffic does not stop.
Day-to-day operation (adding destinations, restarting, rescuing a false positive) is in `docs/mitm-runbook.md`.
The design is in the "段階8 MITM" section of `docs/design.md` (both in Japanese).

### Virus inspection (antivirus)

Downloads in opened traffic are passed to **ClamAV** (a free virus-scanning tool) for inspection.
You install ClamAV's resident part (`clamd`) separately.
`--clamd` takes the path of the `clamd` socket or an `addr:port`.

```
./target/release/packetdeath proxy --listen 127.0.0.1:8899 --blocklist pdtrial/blocklist.txt --mitm-list pdtrial/mitm-list.txt --ca-dir pdtrial/ca --clamd <path of the clamd socket> --deny 403 --log-dir pdtrial/log
```

There are three outcomes.

| Result | What the user sees |
|---|---|
| Judged bad (FOUND) | A `403` replaces the file. The logs show `"reason":"av"` in `flows.jsonl` and `malicious` in `av.jsonl` |
| Judged clean (OK) | The file is passed on as it is, and `av.jsonl` gets a `clean` line |
| Could not inspect (clamd did not answer, timeout, size limit) | The file is passed on as it is, and a `[warn]` is printed |

When it cannot inspect, it leans toward letting the file through (fail-open).
That way a stopped scanner does not stop the user's downloads.
The cost is that a file it could not inspect arrives uninspected.

A response is inspected only when all of these hold.

- It is a `200` response to a `GET`, with a `Content-Length` of at least 1 byte and at most 8191 MiB.
  A response with no `Content-Length` is also inspected, and inspection is given up once the body exceeds 8191 MiB.
- It carries `Content-Disposition: attachment`, or its `Content-Type` is not a page component (`text/html`, `image/*`, `video/*`, `application/json`, and similar).
- `Content-Encoding` is absent or `identity`.

Three measures keep inspection from slowing things down.

- Only downloads are inspected, and page components and video are passed without inspection.
- To replace a bad file with a `403`, it receives the whole body before inspecting.
  A file under inspection therefore does not reach the device by even 1 byte until inspection ends.
- The wait is capped at 1260 seconds, after which it gives up and passes the file.
  A new zip inspected for the first time took 4.6 seconds for 16 files and 9 to 10 seconds for 679 files (measured on 2026-10-03).

Some files pass without inspection.

- Files over 8191 MiB.
- Resumed downloads (`206`).
- Password-protected archives.
- Responses delivered compressed with `br` or `gzip`.
- Files that pose as page components.
- Downloads that arrive while the inspection budget (8 GiB of bodies held at once) is used up.

The detection rate depends on the quality of ClamAV's signatures.
The project cannot say that it prevents malware.
It inspects only files that come from destinations on `--mitm-list`.
It does not inspect files that arrive by USB or by traffic that bypasses the proxy.

### Ads inside encrypted traffic

What it can do: stop ad traffic connection by connection, even when encrypted, by the name it connects to (SNI) and the destination IP.
What it cannot do: remove only the ad portion from the content of opened traffic.

packetdeath opens encrypted traffic only to inspect downloaded files.
Whether something is an ad is still decided by name and destination, not by the content seen after opening.
Ads served under the site's own name, and ads stitched into a video, cannot be stopped.

## Active defense (preparing for certificate incidents)

**Active defense** (stage 10) applies certificates and destinations that public announcements and lists call bad to your traffic before an incident reaches you.
The trigger was the compromise of intermediate certificates of the certificate authority eMudhra.

An **intermediate certificate** is a certificate that a certificate authority (the issuer of identity cards) hands to a subordinate issuer.
Whoever holds a compromised intermediate certificate can show a convincing fake site to any device that trusts it.

The facts about the incident are split here into what was checked and what was not.

| Fact | How it was checked |
|---|---|
| The compromise was a leak of private keys, not weak keys. Multiple intermediate certificates were compromised. The signing roots (top-level certificates) are "Comodo AAA Services" and "emSign ECC Root CA - G3", and they are in the trust store of Red Hat products. In the Go ecosystem it is tracked as CVE-2026-111943 | Read Red Hat's bulletin RHSB-2026-012 (retrieved 2026-10-22) |
| The number of compromised intermediate certificates is 8 | Not confirmed (NOT VERIFIED). Red Hat's bulletin gives no count, Mozilla's announcement could not be retrieved, and the design document treats the number as transcribed |
| The number of eMudhra and emSign records in Mozilla's revocation list (OneCRL) | The feed logs one line, `onecrl emudhra=<n>`. Read the number to confirm it (NOT VERIFIED) |

packetdeath prepares in four ways.

1. **Import the distrust lists daily.** `scripts/pd-malware-feed.sh` fetches OneCRL (Mozilla's list of revoked certificates) and the certificate fingerprints of SSL Blacklist, and converts them into `distrust-onecrl.txt` and `sslbl-certs.txt`.
2. **Stop destinations that use such a chain.** When the certificate chain of a destination (the sequence from the root to the destination) contains a certificate on the list you passed with `--distrust <file>`, the connection is cut.
   For opened traffic (stage 8), the TLS chain to the destination is checked.
   For traffic that is not opened, `--probe-chains` makes packetdeath open a separate TLS connection to the same destination, read the chain, and stop later connections to destinations with a distrusted chain.
   This check connection also sends, as a plain-text SNI, the name of a destination that the client hid with ECH.
   An observer on the path can see the name that was meant to be hidden (whether Chrome uses ECH through a proxy is NOT VERIFIED).
3. **Watch first.** `--watch-distrust`, `--watch-blocklist` and `--watch-iplist` only write hits to `watch.jsonl` and stop nothing.
   `packetdeath defense-report --watch <watch.jsonl>` counts hits per source and prints `promote=yes` when conditions are met, such as 7 days of records and 0 allowlisted hits.
   A person decides whether to move a source to the blocking side.
4. **Avoid stopping too much.** See the next section.

For announcements that exist only as text, with no machine-readable list, the operator adds one line to `distrust-manual.txt`.
That file starts on the watch side (`--watch-distrust`).
There is no feature that reads announcement text by machine and puts it on a list, because one wrongly added line would stop traffic.

### How a compromised eMudhra certificate is avoided

The operating system and the browser still keep the roots above the compromised intermediates (such as "Comodo AAA Services") in their trust stores.
A fake site built on a compromised intermediate therefore looks like a valid certificate to the operating system and the browser alone.
packetdeath stops it before that point, in this order.

1. Every day, `scripts/pd-malware-feed.sh` fetches Mozilla's OneCRL (the list of revoked certificates) and writes `distrust-onecrl.txt`.
   Each line is either a fingerprint of a certificate's public key (`spki-sha256`) or an issuer name and serial number pair (`issuer-serial`).
   The number of eMudhra and emSign lines appears in the feed log as `onecrl emudhra=<n>`.
2. When the PC's traffic goes through the proxy, packetdeath checks every certificate in the chain the destination presents (the site certificate, the intermediate, and the root above it) against that list.
   For traffic it does not open, `--probe-chains` opens a separate TLS connection to the same destination to read the chain.
3. If any certificate in the chain matches a line on the list, packetdeath cuts the connection to that destination and records `"reason":"chain"` in `flows.jsonl`.
   Even though the operating system trusts the root, a chain that passes through a compromised intermediate stops here.
4. Legitimate sites that use an uncompromised intermediate under the same root do not match the list and are not stopped.

This flow assumes the compromised intermediates are on OneCRL.
A fake site that appears before they are listed, and the first connection before `--probe-chains` has read the chain, still get through (see the limits above).

### Undoing an over-block

| What happened | How to undo | Takes effect in |
|---|---|---|
| One destination was stopped by mistake | Add its name to the allowlist, one line. The allowlist wins over a distrusted chain | About 0.3 seconds |
| You want the whole blocking side of active defense back on watch-only | Create the file you gave to `--defense-off <path>` (`touch <path>`). Delete it to restore | About 0.3 seconds |
| One list stopped more than `--breaker-hosts` destinations (default 5) in 10 minutes | A safety valve (breaker) drops that list alone to watch-only | The next decision after a hit |

While the `--defense-off` file exists, only blocking by the distrust lists and by the chain check (`--probe-chains`) is switched off.
The ad blocklist and the allowlist keep working.
The default of 5 for `--breaker-hosts` is provisional (ASSUMPTION) and will be decided again from the watch records.

### Terms of the imported lists

OneCRL, Feodo Tracker and SSL Blacklist are fetched without a key.
ThreatFox and URLhaus are for users authenticated at abuse.ch, so when the `--auth <key file>` file is missing or its mode is looser than `0600`, no request is sent to them.
In that case `malware-domains.txt` and `malware-ips.txt` stay as they were and grow stale, and the script ends with `rc=1`.
Getting a key requires you to authenticate at abuse.ch yourself.

### Limits

- The first connection passes, because the chain check runs after the connection is let through.
- Active defense is wired into `proxy`, so it does not reach traffic that bypasses the proxy (tools that do not read the automatic configuration) or the Windows service path.
- The chain check is not on the `block` path (traffic of tools on this machine).
- The lists are only OneCRL, SSL Blacklist and the lines you add by hand. Chrome's revocation list (CRLSet) and Microsoft's distrust list are not included.
- The text of Mozilla's announcement could not be read when the design document was written (NOT VERIFIED).

The design and acceptance IDs are in the "段階10 能動防御" section of `docs/design.md` (in Japanese).

## Importing outside lists

`scripts/pd-malware-feed.sh --out <output folder> [--auth <key file>]` fetches public lists and converts them into the form packetdeath reads.
packetdeath itself never starts this script or fetches any list.
It runs with `curl`, `sh` and `jq`.

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

- The logs (`flows.jsonl`, `dns.jsonl`, `av.jsonl`, `watch.jsonl`) contain the destinations the device connected to.
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
