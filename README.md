# packetdeath

[日本語](README.ja.md) | English

packetdeath stops connections to ads and to known-bad sites with a watcher program that runs outside your browser.
The watcher compares the name of each destination with a list, and cuts only the connections whose names are on the list.

It is not a browser extension, so it does not rewrite anything inside the browser.
You can also point other devices in your home, such as an iPhone, at the same watcher.

The meaning of every command and option is in "Commands and options".
If you use Windows, read "Using it on Windows" first.
It covers getting the executable, where to put it, auto-start, and removal, in order.

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
| 11 WAF | A reverse proxy in front of your web server that scores every request against built-in rules and refuses, or only records, those over the threshold; it also limits rates and bans repeat offenders | `waf` `waf-test` `waf-report` |
| 12 IPS policy | Decides per Suricata alert whether to stop, record or ignore, waits for repeated alerts before stopping, never stops the gateway, resolvers or loopback, keeps stopped destinations across a restart, and writes an audit log | `--ips-policy` `--ips-never` `--ips-state` `ips-test` `ips-report` |
| 13 WebApp | A browser console (Rust server, Dioxus screens in WebAssembly) to sign in (password plus a second factor: an authenticator app with a QR code and recovery codes, or a passkey), manage users with roles, edit the IPS, IDS, WAF and antivirus settings with the tool's own parsers checking every save, start from baseline rules, and read the WAF and IPS status | `webapp/` (`packetdeath-webapp --data --config --logs --static`). See "webapp: the browser console" |

Stages 4 to 12 are explained in "Details" and "Active defense".
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
| Windows service | Designed to read the capture left by the Windows built-in capture tool (**pktmon**) and cut established connections. Recording has worked; cutting has not been confirmed (PW-7 did not pass) | Needed | Windows 11 (recording only) |

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
   git clone https://github.com/fukugan-ai/packetdeath.git
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
  To change that range, pass `--allow-from <CIDR>` (if you pass even one, the default ranges are not used and only the ones you pass apply).
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

## Using it on Windows

In short: if you use Windows alone, method A (running the proxy inside Windows) is the one to use.
If you have no WSL or Linux machine, choose A.
If a Linux or WSL machine sits on the same LAN, method B (using the proxy of another machine) is also open to you.
Method C (a Windows service) can record destinations, but it has not been shown to stop a connection (acceptance PW-7 did not pass).
To stop traffic, use A or B.

The start-up, blocking and PAC delivery of method A were checked on a real Windows machine (2026-10-22).
The conditions were: administrator rights, the watcher listening on `127.0.0.1:18899`, the PAC fetched with `curl`, and no OS proxy setting entered.
A run without administrator rights has not been checked (NOT VERIFIED).
The results: `example.com` returned `200`, a `CONNECT` to `events.data.microsoft.com` returned `403`, and `/proxy.pac` returned `200` with the body `PROXY 127.0.0.1:18899; DIRECT`.
Two `[warn]` lines about content inspection and active defense appeared, and the watcher kept running.
Registering the Task Scheduler task, the OS PAC setting, and placing the file in `C:\Program Files` were not checked (NOT VERIFIED).
The proxy is built for every OS (`pub mod proxy;` in `src/lib.rs`).

| | A: proxy inside Windows (recommended) | B: proxy on another machine | C: Windows service (experimental) |
|---|---|---|---|
| Where the watcher runs | Inside Windows. No Linux or WSL needed | A Linux or WSL machine on the same LAN | Inside Windows |
| Stopping a destination | It stops. On a real Windows machine a `CONNECT` returned `403` (conditions above) | It stops. Checked with `curl` from Linux. A real run through a Windows proxy setting is NOT VERIFIED | Not confirmed. If the cut fails, `flows.jsonl` stays `pass` and the connection continues (PW-7 did not pass; `rc=87` on a real machine on 2026-10-04) |
| Inspecting content (virus scan) and active defense | Not available. If you pass the options, it prints a `[warn]` and starts with only that feature off | Available (when the watcher runs on Linux) | Not available |
| After a reboot | Task Scheduler starts it at logon. A real run is NOT VERIFIED | The Windows setting stays. On the proxy side, start the watcher again on the Linux machine | The service is set to start by itself. A real run is NOT VERIFIED (PW-8 has not been run) |
| What you have to keep running | Nothing | Starting the watcher on the proxy side | The pktmon capture and conversion (step 6 of method C). While you do not run it, nothing is recorded or stopped |

On Windows, the counterpart of an auto-start is the Task Scheduler registration in A, the Windows proxy setting in B, and the service registration in C.

```
A: download the exe from the Release -> put it on Windows -> start the proxy -> enter the PAC URL -> auto-start by task -> check -> remove
B: start the watcher on Linux -> enter the PAC URL in Windows -> check -> remove
C: build the exe -> put it on Windows -> register -> run pktmon -> check -> remove
```

In short, you put an executable on Windows only for A and C.
In B the watcher runs on the Linux side.

### Getting the executable (packetdeath.exe)

The prebuilt executable is published as a GitHub Release.
If the latest Release has no `packetdeath-x86_64-windows.exe` (the list is empty), use "Building it yourself" below.

1. In a browser, open <https://github.com/fukugan-ai/packetdeath/releases/latest> and save `packetdeath-x86_64-windows.exe` and `packetdeath-x86_64-windows.exe.sha256` to `Downloads`.
2. Open PowerShell and go to `Downloads`.

   ```
   cd "$HOME\Downloads"
   ```

3. Compare the hash (the fingerprint of the file) of the downloaded file with the value written in the `.sha256` file.
   The `.sha256` file holds `<64 letters and digits>  packetdeath-x86_64-windows.exe` (checked on 2026-10-22).
   The command below prints `True` when they are the same and `False` when they differ.
   PowerShell's `-eq` ignores the difference between upper and lower case.

   ```
   (Get-FileHash .\packetdeath-x86_64-windows.exe -Algorithm SHA256).Hash -eq ((Get-Content .\packetdeath-x86_64-windows.exe.sha256) -split ' ')[0]
   ```

4. If it prints `True`, rename the file to `packetdeath.exe`.
   If it prints `False`, delete the file without running it.

   ```
   Rename-Item .\packetdeath-x86_64-windows.exe packetdeath.exe
   ```

The first time you run it, Windows SmartScreen (the feature that warns about unfamiliar executables) may show a warning.
If it does, choose "More info", then "Run anyway".
The wording on screen is NOT VERIFIED (the Microsoft Learn page that was read did not give it).

#### Building it yourself

Build it on Linux or WSL.

1. Check for the mingw-w64 linker.
   `x86_64-w64-mingw32-gcc --version` should print a version.
   If it is missing, on Debian and Ubuntu `sudo apt install gcc-mingw-w64-x86-64` installs it (the package name is NOT VERIFIED).
2. Add the Windows standard library.

   ```
   rustup target add x86_64-pc-windows-gnu
   ```

3. Build.

   ```
   cargo build --release --target x86_64-pc-windows-gnu
   ```

4. Check the result.
   The build produces `target/x86_64-pc-windows-gnu/release/packetdeath.exe`.
   The output of `file` should contain `PE32+ executable`.

   ```
   file target/x86_64-pc-windows-gnu/release/packetdeath.exe
   ```

5. Copy this file to the Windows `Downloads` folder, for example with a USB stick or a shared folder.

### Method A: run the proxy inside Windows

Steps 3 to 5 (start-up, blocking, PAC delivery) were checked on a real Windows machine; the conditions are written at the start of this section.
Placing the file in `C:\Program Files` (step 1), entering the PAC setting in the OS (step 5) and the Task Scheduler (step 6) were not checked (NOT VERIFIED).

On Windows the proxy can block by SNI and by destination.
The options `--mitm-list`, `--ca-dir` and `--clamd` (inspecting content) and the active-defense options (such as `--distrust`) are turned off on Windows, and each prints a `[warn]` (the `proxy` start-up in `src/main.rs`).

1. Open an administrator PowerShell and move the executable to its home.
   The steps are the same as steps 1 and 2 of method C.
2. Create the folder for logs and lists, and write one destination to stop.
   The steps are the same as step 3 of method C.
3. Start the watcher in the foreground.
   It prints a startup line and keeps waiting.
   To stop it, press `Ctrl+C` in that window.

   ```
   & 'C:\Program Files\packetdeath\packetdeath.exe' proxy --listen 127.0.0.1:8899 --blocklist 'C:\ProgramData\packetdeath\blocklist.txt' --deny 403 --log-dir 'C:\ProgramData\packetdeath'
   ```

   The first time, Windows Defender Firewall may show a window asking whether to allow it.
   According to the Microsoft Learn documentation, when an app without an allow rule listens for the first time, a window appears, and answering "No" or closing it creates block rules (retrieved 2026-10-22).
   If the watcher listens only on `127.0.0.1` (inside this machine), no allow rule should be needed.
   Whether the window appears, and whether the block rules affect `127.0.0.1` traffic, are NOT VERIFIED.
   If it appears, do not grant access to any network.
4. In another PowerShell window, connect to the destination on the list.
   The connection is cut with a `403`.

   ```
   curl.exe -sS -x http://127.0.0.1:8899 https://example.org/
   ```

   The output is `curl: (7) CONNECT tunnel failed, response 403` (this wording from `curl.exe` on Windows is NOT VERIFIED; on a real machine a `CONNECT` was confirmed to return `403`).
   Also check that an ordinary site that is not on the list opens.
   You want `200`.

   ```
   curl.exe -sS -o NUL -w '%{http_code}\n' -x http://127.0.0.1:8899 https://example.com/
   ```

   The log is `C:\ProgramData\packetdeath\flows.jsonl`, one line per connection.
   A destination that was stopped has `"decision":"block"` in its line, and one that was let through has `"decision":"pass"`.

   ```
   Get-Content 'C:\ProgramData\packetdeath\flows.jsonl' -Tail 4
   ```

5. Enter an automatic proxy configuration URL in the Windows proxy settings.
   The screens are the same as steps 2 to 6 of method B, and only the script address differs: `http://127.0.0.1:8899/proxy.pac`.
   That the watcher serves `/proxy.pac` was checked with `curl` (it returned `PROXY 127.0.0.1:18899; DIRECT`).
   Whether the Windows setting reads it and routes traffic accordingly is NOT VERIFIED.
6. Register it in Task Scheduler so that it starts at logon.
   Open Command Prompt as administrator and run the command there.
   To open it, search for "cmd" in the Start menu and choose "Run as administrator" (the wording on screen is NOT VERIFIED).
   Do not use PowerShell, because it may handle quotation marks differently (NOT VERIFIED).
   `/sc onlogon` means "run every time a user logs on".
   `/tr` is the command to run, at most 262 characters including the path.

   ```
   schtasks /create /tn "packetdeath proxy" /sc onlogon /tr "\"C:\Program Files\packetdeath\packetdeath.exe\" proxy --listen 127.0.0.1:8899 --blocklist C:\ProgramData\packetdeath\blocklist.txt --deny 403 --log-dir C:\ProgramData\packetdeath"
   ```

   Stop the window of step 3 with `Ctrl+C`, then start the task at once without logging on again.

   ```
   schtasks /run /tn "packetdeath proxy"
   ```

   The `schtasks` arguments were checked against the Microsoft Learn page for `schtasks create` (retrieved 2026-10-22).
   The nested quotation marks (`\"`) and how the watcher's window looks once started are NOT VERIFIED.
   Traffic before logon is not stopped, because the watcher is not running yet.
7. Run the `curl.exe` command of step 4 again, and check in a browser that a destination on the list does not open.
8. To remove it, delete the setting, the task and the folders.
   First, turn "Use setup script" off in the screen of step 5 and save.

   ```
   schtasks /end /tn "packetdeath proxy"
   schtasks /delete /tn "packetdeath proxy" /f
   Remove-Item -Recurse 'C:\Program Files\packetdeath'
   Remove-Item -Recurse 'C:\ProgramData\packetdeath'
   ```

   Run the first two lines in Command Prompt and the last two in an administrator PowerShell.
   If the watcher stops, the automatic configuration falls back to `DIRECT` (a direct connection), so traffic does not stop.

### Method B: use the proxy of another machine

A proxy is a relay for your traffic.
An **automatic proxy configuration URL** (PAC) is the location of a small file that says which traffic goes to the relay.
The watcher serves it at `/proxy.pac`.

1. Start the watcher on Linux or WSL.
   Give `--listen` the LAN IP of that machine (`hostname -I` shows it).
   With WSL, check that Windows can reach that IP (NOT VERIFIED).

   ```
   ./target/release/packetdeath proxy --listen 192.0.2.10:8899 --blocklist pdtrial/blocklist.txt --deny 403 --log-dir pdtrial/log
   ```

   Step 3 of the quick start shows how to make the list and the log folder.
   To keep it running across reboots, register this command for automatic start on the Linux side.
   No systemd unit for the proxy ships with the repository (`scripts/systemd/` holds `packetdeath-block.service` for `block` and two files for the list import).
2. Open Windows 11 Settings.
3. Choose "Network & internet", then "Proxy".
4. Next to "Use setup script", choose "Set up".
5. Turn on "Use setup script".
6. Enter `http://192.0.2.10:8899/proxy.pac` as the script address and choose "Save".

The labels follow the Microsoft support article (retrieved 2026-10-22).
They can differ between Windows versions, and the screen on a real machine is NOT VERIFIED.

Check it in two ways.

- In a browser, open a destination that is on the list (for example `https://example.org/`).
  It should fail to open and show an error.
- Open an ordinary site that is not on the list (for example `https://example.com/`).
  It should open.

If the watcher stops, the automatic configuration falls back to `DIRECT` (a direct connection), so traffic does not stop.

To remove it, turn "Use setup script" off in the screen of step 4 and save.

### Method C: register it as a Windows service

Registering alone stops nothing.
To record destinations, you have to keep capturing with pktmon and converting to pcapng.
packetdeath does not start pktmon (this avoids the accident of a forgotten capture).
Whether it can stop a connection has not been confirmed, because PW-7 did not pass.
If the cut fails, the traffic continues and the `decision` in `flows.jsonl` stays `pass`.

1. Open an administrator PowerShell.
   Search for "PowerShell" in the Start menu and choose "Run as administrator" (the wording on screen is NOT VERIFIED).
2. Move the executable to its home.

   ```
   New-Item -ItemType Directory -Force 'C:\Program Files\packetdeath'
   Copy-Item "$HOME\Downloads\packetdeath.exe" 'C:\Program Files\packetdeath\packetdeath.exe'
   ```

   Do this before registering, because the service registers the location of the very executable that ran the registration.
   If you register from `Downloads`, that temporary location is what gets registered.
3. Create the folder for logs and lists, and write one destination to stop.

   ```
   New-Item -ItemType Directory -Force 'C:\ProgramData\packetdeath'
   Set-Content -Path 'C:\ProgramData\packetdeath\blocklist.txt' -Value 'example.org' -Encoding ascii
   ```

4. Register the service.
   `--log-dir` is required.
   Give `--pcapng` the location of the `capture.pcapng` that step 6 creates.

   **pcapng**: a file format for recorded network traffic. Many analysis tools, such as Wireshark, read it.
   `capture.pcapng` is the pktmon capture (`.etl`) converted with `pktmon etl2pcap`. The service rereads this file about every 0.3 seconds and compares the destination names of the connections in it with the blocklist.
   Without `--pcapng` there is nothing to read, so the service neither records nor stops anything (it starts and only waits for a stop signal).
   The details of `--pcapng` are in "Commands and options", under "`--pcapng`: the entrance for the pktmon capture".

   ```
   & 'C:\Program Files\packetdeath\packetdeath.exe' service-install --log-dir 'C:\ProgramData\packetdeath' --pcapng 'C:\ProgramData\packetdeath\capture.pcapng' --blocklist 'C:\ProgramData\packetdeath\blocklist.txt'
   ```

   The start type is automatic with a delay (delayed-auto), and the account is LocalSystem.
   After a crash it restarts after 5, 30 and 60 seconds, and the count resets after 24 hours.
5. Start the service and check it.
   Registering does not start it (`service-install` makes no start call).

   ```
   Start-Service packetdeath
   Get-Service packetdeath
   ```

   According to Microsoft's documentation, `Get-Service` prints three columns: `Status`, `Name` and `DisplayName`.
   You want `Running` in `Status`.
   The actual output for this service is NOT VERIFIED.
6. Capture with pktmon and convert to pcapng.
   **pktmon** is the packet capture tool built into Windows.
   `.etl` is the format of its capture, and `.pcapng` is the format packetdeath reads.

   ```
   pktmon filter add pd7 -t TCP -p 443
   pktmon start --capture --comp nics --pkt-size 0 --flags 0x010 --file-name C:\ProgramData\packetdeath\capture.etl
   ```

   Make some traffic, then stop and convert.

   ```
   pktmon stop
   pktmon etl2pcap C:\ProgramData\packetdeath\capture.etl --out C:\ProgramData\packetdeath\capture.pcapng
   ```

   The service looks at `capture.pcapng` about every 0.3 seconds and rereads it when it has changed.
   Nothing that repeats the capture and conversion automatically ships with the repository.
   After a reboot, the service records nothing until you run step 6 again.
   The wording of pktmon's output is also unconfirmed in the design document (NOT VERIFIED).
7. Read the log.

   ```
   Get-Content 'C:\ProgramData\packetdeath\flows.jsonl' -Tail 5
   ```

   The service's own log is `C:\ProgramData\packetdeath\service.log`.
8. Clean up.
   If you forget to stop a pktmon capture, the capture file grows without limit.
   `.etl` and `.pcapng` hold the destinations your device connected to, so delete them.

   ```
   pktmon stop
   pktmon filter remove
   pktmon status
   Remove-Item 'C:\ProgramData\packetdeath\capture.etl', 'C:\ProgramData\packetdeath\capture.pcapng'
   ```

9. To remove the service, stop it and then delete the registration.

   ```
   Stop-Service packetdeath
   & 'C:\Program Files\packetdeath\packetdeath.exe' service-uninstall
   Remove-Item -Recurse 'C:\Program Files\packetdeath'
   Remove-Item -Recurse 'C:\ProgramData\packetdeath'
   ```

   The service installs no extra driver, so the registration and these two folders are all there is to remove.
   Deleting `C:\ProgramData\packetdeath` deletes the logs too.

## Commands and options

The usage is `packetdeath <command> [option ...]`.
A **command** is the first word, which chooses what to do (such as `proxy` or `block`).
An **option** is a setting that changes how a command works. It starts with `--`, and most take one value (`--listen 127.0.0.1:8899`).

How to read the values:

- `<path>`: the location of a file or a folder.
- "Repeatable": you can pass the same option several times. The lists you pass are used together (their union).
- **CIDR**: a way to write a range of IPs (`192.168.0.0/16` means 192.168.0.0 to 192.168.255.255).
- A list file ignores lines that start with `#`.
  If you edit a list (blocklist, allowlist, iplist, `--mitm-list`) while the program runs, it is reread.
  The interval depends on the path.
  Linux `block` (the nfqueue path), `proxy` and the Windows service reread in about 0.3 seconds (a fixed 300 milliseconds for the service).
  `block --pcapng` rereads at each poll of the `--pcapng` file (`--poll-ms`, default 1000 milliseconds).
  A list that cannot be read is treated as an empty list and a `[warn]` is printed (startup does not stop).
  There are two exceptions.
  If the `--av` file cannot be read, it is treated as empty but an `[error]` is printed.
  `defense-report` fails instead of treating a file as empty when any file cannot be read (an empty list would show `hits=0` and look clean).

This section was written from the argument parsing in `src/main.rs` and the usage lines in `src/i18n.rs`.
Running `packetdeath` with no arguments prints the usage lines.

| Command | What it does | OS |
|---|---|---|
| `observe` | Records destinations in `flows.jsonl` without stopping anything | Linux only. On Windows it prints "not implemented" and exits |
| `block` | Cuts connections to destinations on a list | Linux (nfqueue). On Windows `--pcapng` is required |
| `eval` | Compares the log with a table of right answers and prints the stop rate and the wrongly-stopped rate | Both |
| `filterlist` | Converts an EasyList-format list into the blocklist format | Both |
| `allowlist-convert` | Converts a public allowlist into the allowlist format | Both |
| `service-install` | Registers it as a Windows service | Windows only |
| `service-uninstall` | Deletes the service registration | Windows only |
| `service-run` | The body of the service. The service manager (SCM) starts it; users do not type it | Windows only |
| `proxy` | Acts as a relay and cuts connections to destinations on a list | Both. Content inspection and active defense are Linux only |
| `defense-report` | Counts the hits in the watch logs and shows whether a list may move to the blocking side | Linux only |
| `waf` | A web application firewall: a reverse proxy in front of your web server that judges every request before the server sees it | Both |
| `waf-test` | Runs a file of sample requests through the same judge, without a network, and lists the ones judged differently from what you expected | Both |
| `waf-report` | Counts the WAF audit log: actions, rules that fired, busiest sources, rules that look like false positives | Both |
| `ips-test` | Runs a file of Suricata alerts through an IPS policy without a network, and prints what each alert would get | Both |
| `ips-report` | Counts the IPS audit log: events, signatures that stopped traffic, signatures that only observed, protected destinations | Both |

If you do not pass `--log-dir`, the log folder is `$XDG_STATE_HOME/packetdeath` (or `$HOME/.local/state/packetdeath` if that is unset) on Linux, and `%LOCALAPPDATA%\packetdeath` on Windows.
Only `service-install` and `service-run` require `--log-dir`, because the service runs as SYSTEM and `%LOCALAPPDATA%` is different there.

### observe: record without stopping

It records the destinations of traffic that was sent to nfqueue.
It does not stop anything.

| Option | Value | What it does | Default | Required |
|---|---|---|---|---|
| `--queue` | number | The nfqueue number that receives the traffic. Use the same value as `--queue-num` in the iptables rule | 1808 | Optional |
| `--filter` | expression | An option that is accepted but not used. On Linux it is ignored with a `[warn]`. On Windows `observe` itself is not implemented | None | Optional |
| `--log-dir` | `<path>` | The folder for `flows.jsonl` | The default location above | Optional |

```
sudo iptables -I OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num 1808 --queue-bypass
sudo ./target/release/packetdeath observe --queue 1808 --log-dir ./log
```

### block: cut destinations on a list

On Linux it judges the traffic that was sent to nfqueue and cuts it.
On Windows it reads the capture that you pass with `--pcapng` and judges that (see the next part).

| Option | Value | What it does | Default | Required | OS |
|---|---|---|---|---|---|
| `--queue` | number | The nfqueue number that receives the traffic | 1808 | Optional | Linux |
| `--blocklist` | `<path>` | The list of names to stop. Repeatable | None (empty list) | Optional | Both |
| `--allowlist` | `<path>` | The list of names to always let through. It is checked before the blocklist | None (empty list) | Optional | Both |
| `--iplist` | `<path>` | The list of IPs and CIDRs to stop, one per line. Repeatable | None (empty list) | Optional | Both |
| `--av` | `<path>` | The `av.jsonl` that an outside scanner wrote. The (IP, port) pairs of `malicious` lines are stopped | None (empty) | Optional | Both |
| `--dns` | no value | Also cuts connections whose DNS alias (CNAME) points to a listed name. Records DNS answers in `dns.jsonl` | Off | Optional | Linux. Not used on the `--pcapng` path |
| `--eve` | `<path>` | The location of the `eve.json` where Suricata writes alerts | None (no cut because of alerts) | Optional | Linux. Not used on the `--pcapng` path |
| `--ips-sids` | `<path>` | The list of alert rule numbers (sids) to stop, one per line | None | Optional | Linux. Same |
| `--ips-severity` | 1 to 3 | Stops alerts whose severity is this value or lower. 1 is the most severe | None (no cut by severity) | Optional | Linux. Same |
| `--ips-ttl` | seconds | How long a destination stopped because of an alert stays stopped | 300 | Optional | Linux. Same |
| `--ips-policy` | `<path>` | A rule file (one JSON object per line, first match wins) that says per alert whether to stop, only record, ignore, or stop after repeated alerts. Replaces `--ips-sids` and `--ips-severity` | None (the older options apply) | Optional | Linux. Needs `--eve`. Not together with `--ips-sids` or `--ips-severity` |
| `--ips-never` | `<path>` | Addresses or CIDRs that are never stopped, one per line | None | Optional | Needs `--ips-policy` |
| `--ips-allow-private` | no value | Lets the policy stop private (LAN) destinations. Loopback, link-local, multicast, this host, the gateway and the resolvers stay protected | Off (private destinations are protected) | Optional | Needs `--ips-policy` |
| `--ips-default` | `drop`, `alert` or `ignore` | What an alert gets when no policy line matches | `alert` (record only) | Optional | Needs `--ips-policy` |
| `--ips-max-entries` | count | Upper limit of stopped destinations and of the repeat-alert table. The entry that expires first is dropped when full | 16384 | Optional | Needs `--ips-policy` |
| `--ips-state` | `<path>` | A file that keeps the stopped destinations across a restart. Entries whose time has passed are not restored | None (lost on restart) | Optional | Needs `--ips-policy` |
| `--eve-max-read` | bytes | The most `eve.json` bytes read in one poll | 8388608 | Optional | Needs `--ips-policy` |
| `--eve-stale` | seconds | Warns when `eve.json` has not changed for this long (Suricata may have stopped) | 900 | Optional | Needs `--ips-policy` |
| `--pcapng` | `<path>` | The location of the pktmon capture converted with `pktmon etl2pcap` (next part) | None | Required on Windows | On Windows it cuts. On Linux it only judges and records, never cuts, and prints a `[warn]` |
| `--poll-ms` | milliseconds | How often the `--pcapng` file is reread | 1000 | Optional | Together with `--pcapng` |
| `--log-dir` | `<path>` | The folder for `flows.jsonl` and `dns.jsonl` | The default location above | Optional | Both |

The options used on the `--pcapng` path are `--blocklist`, `--allowlist`, `--iplist`, `--av`, `--poll-ms` and `--log-dir` (`run_block` in `src/main.rs`).

```
sudo ./target/release/packetdeath block --queue 1808 --blocklist blocklist.txt --allowlist allowlist.txt --log-dir ./log
```

### --pcapng: the entrance for the pktmon capture

**pcapng** is a file format for recorded network traffic.
Many analysis tools, such as Wireshark, read it.
What pktmon on Windows captures is saved in another format, `.etl`, so you convert it to `.pcapng` with `pktmon etl2pcap`.
packetdeath can read the `.pcapng` one.

```
traffic -> pktmon captures it (capture.etl) -> pktmon etl2pcap converts it (capture.pcapng) -> --pcapng hands it to packetdeath
```

In short, `--pcapng` is the location of the capture file to read, and packetdeath never captures traffic by itself.

packetdeath rereads the `--pcapng` file at a fixed interval and compares the destination names (SNI) of the connections in it with the lists.
The interval is `--poll-ms` for `block` (default 1000 milliseconds) and a fixed 300 milliseconds for the Windows service.
If the file has the same size as last time, it skips the reread.

Without `--pcapng` there is nothing to read, so the service records nothing and cuts nothing.
It starts and only waits for a stop signal.
Without `--pcapng`, `block` prints "not implemented" and exits on Windows, and runs on the nfqueue path on Linux.

Nothing that keeps the pktmon capture and conversion running ships with this repository.
packetdeath does not start `pktmon`, to avoid the accident where a capture is left running after packetdeath dies and the file grows without limit.
A note in `src/win_service.rs` says that the interval at which the pktmon capture is switched (rotated) was shortened to 3 seconds on a user's PC during testing.
The script that does that rotation is not in this repository.
While `capture.pcapng` is not updated, new traffic is not judged.

### eval: measure the stop rate

It compares `flows.jsonl` with a table of "host, and ad or ok" (the labels).

| Option | Value | What it does | Default | Required |
|---|---|---|---|---|
| `--labels` | `<path>` | The table of right answers. One line is "host, tab, `ad` or `ok`". Lines in the wrong shape are ignored | None | Required |
| `--log-dir` | `<path>` | The folder to read `flows.jsonl` from. If it is missing, it counts as 0 lines | The default location above | Optional |

```
./target/release/packetdeath eval --labels labels.tsv --log-dir ./log
```

### filterlist and allowlist-convert: convert lists

Both only read and write files and never touch the network.
`filterlist` turns the EasyList format into a blocklist, and `allowlist-convert` turns a public allowlist (Microsoft's JSON, one domain per line, or the Adblock Plus `@@` format) into an allowlist.

| Option | Value | What it does | Default | Required |
|---|---|---|---|---|
| `--in` | `<path>` or `-` | The file to read. `-` is standard input | None | Required |
| `--out` | `<path>` or `-` | The file to write. `-` is standard output | None | Required |

```
./target/release/packetdeath filterlist --in easylist.txt --out blocklist.txt
```

### service-install and service-uninstall: register and delete the Windows service

Run `service-install` in an administrator PowerShell.
The options it receives are written into the service's start-up arguments and passed on to `service-run`.
`service-uninstall` takes no option.

| Option | Value | What it does | Default | Required |
|---|---|---|---|---|
| `--log-dir` | `<path>` | The folder where the service puts `flows.jsonl` and `service.log` | None | Required |
| `--pcapng` | `<path>` | The capture file to read (previous part). Without it the service neither records nor cuts anything | None | Optional |
| `--blocklist` | `<path>` | The list of names to stop. Only one | None (empty list) | Optional |
| `--allowlist` | `<path>` | The list of names to always let through. Only one | None (empty list) | Optional |

```
& 'C:\Program Files\packetdeath\packetdeath.exe' service-install --log-dir 'C:\ProgramData\packetdeath' --pcapng 'C:\ProgramData\packetdeath\capture.pcapng' --blocklist 'C:\ProgramData\packetdeath\blocklist.txt'
& 'C:\Program Files\packetdeath\packetdeath.exe' service-uninstall
```

### proxy: receive traffic as a relay

It needs no admin rights.
It also runs on Windows.

| Option | Value | What it does | Default | Required | OS |
|---|---|---|---|---|---|
| `--listen` | `addr:port` | The IP and port that receive traffic. There is no default, so that `0.0.0.0` is never opened silently | None | Required | Both |
| `--blocklist` | `<path>` | The list of names to stop. Repeatable | None (empty list) | Optional | Both |
| `--allowlist` | `<path>` | The list of names to always let through | None (empty list) | Optional | Both |
| `--iplist` | `<path>` | The list of IPs and CIDRs to stop. Repeatable | None (empty list) | Optional | Both |
| `--av` | `<path>` | The `av.jsonl` that an outside scanner wrote | None (empty) | Optional | Both |
| `--deny` | `blackhole` or `403` | How a stopped connection is answered. `blackhole` pretends to connect and then stays silent. `403` returns `403 Forbidden` and closes | `blackhole` | Optional | Both |
| `--allow-from` | CIDR | The range of clients it accepts. Repeatable. If you pass even one, the default is not used and only the ranges you pass apply. A value that does not parse as a CIDR is dropped with a `[warn]` ("--allow-from value does not parse as a CIDR"). If none parse, there are 0 entries and no client is accepted | `127.0.0.0/8`, `::1/128`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | Optional | Both |
| `--log-dir` | `<path>` | The folder for `flows.jsonl` and other logs | The default location above | Optional | Both |
| `--mitm-list` | `<path>` | The list of destinations whose encrypted traffic is opened. It works only when all three of this, `--ca-dir` and `--clamd` are given | None | Optional | Linux. On Windows it prints a `[warn]` and stays off |
| `--ca-dir` | `<path>` | The folder that holds the key and certificate of the CA (the certificate issuer) used to open traffic | None | One of the three | Linux. Same |
| `--clamd` | socket path or `addr:port` | The location of `clamd` for virus inspection | None | One of the three | Linux. Same |
| `--distrust` | `<path>` | The list of distrusted certificates. Connections to destinations whose chain contains a listed certificate are cut. Repeatable | None | Optional | Linux. On Windows it prints a `[warn]` and stays off |
| `--watch-distrust` | `<path>` | Applies the same kind of list as `--distrust` but only records hits in `watch.jsonl` and stops nothing. Repeatable | None | Optional | Linux. Same |
| `--watch-blocklist` | `<path>` | Records blocklist hits in `watch.jsonl` without stopping. Repeatable | None | Optional | Linux. Same |
| `--watch-iplist` | `<path>` | Records iplist hits in `watch.jsonl` without stopping. Repeatable | None | Optional | Linux. Same |
| `--probe-chains` | no value | For destinations whose traffic it does not open, packetdeath opens a separate TLS connection and reads the certificate chain. It sends the destination name as a plain-text SNI | Off | Optional | Linux. Same |
| `--defense-off` | `<path>` | While this file exists, blocking by the distrust lists and the chain check is switched off and only recorded (`touch <path>` turns it on; deleting the file restores it) | None | Optional | Linux. Same |
| `--breaker-hosts` | integer of 1 or more | The number of destinations one list may stop in 10 minutes. Beyond it, that list drops to watch-only | 5 | Optional | Linux. Same |

```
./target/release/packetdeath proxy --listen 127.0.0.1:8899 --blocklist blocklist.txt --allowlist allowlist.txt --deny 403 --log-dir ./log
```

If you give only one or two of `--mitm-list`, `--ca-dir` and `--clamd`, it starts with opening disabled and prints the missing option names as a `[warn]`.
The details are in "Opening encrypted traffic (MITM)" and "Active defense".

### defense-report: count the watch logs

It only reads logs and changes neither traffic nor files.
You must pass exactly one of `--flows` and `--watch` (it fails with both, and with neither).

| Option | Value | What it does | Default | Required |
|---|---|---|---|---|
| `--flows` | `<path>` | `flows.jsonl`. Applies lists to a past log and counts the hits | None | `--flows` or `--watch` |
| `--watch` | `<path>` | `watch.jsonl`. Counts hits per source and shows with `promote=yes` or `no` whether it may move to the blocking side | None | Same |
| `--blocklist` | `<path>` | A blocklist used with `--flows`. Repeatable | None | Optional |
| `--iplist` | `<path>` | An iplist used with `--flows`. Repeatable | None | Optional |
| `--allowlist` | `<path>` | Counts separately how many hits are on the allowlist. Repeatable | None | Optional |
| `--distrust` | `<path>` | A distrust list used with `--watch`. Adds `root=yes` to lines that name a public trust anchor (root). Repeatable | None | Optional |
| `--days` | number of days | A lower bound on the days of log required before it says a source may move. The real number of days in the log cannot be raised by this value | 0 (at least 7 days of log are needed) | Optional |

```
./target/release/packetdeath defense-report --flows ./log/flows.jsonl --blocklist blocklist.txt
./target/release/packetdeath defense-report --watch ./log/watch.jsonl --days 7
```

### waf: protect a web server

`waf` stands in front of your own web server (the "upstream") and judges each request before the server sees it.
Each rule a request trips adds points (critical 5, error 4, warning 3, notice 2), and a total that reaches `--threshold` counts as an attack.
It does not end TLS. Put it behind whatever does (nginx, caddy, a cloud front), and keep `--listen` on `127.0.0.1` unless you mean to expose it.
The default mode is `detect`: nothing is refused, and everything is written to `waf.jsonl`.
Read `waf-report` for a while, rescue false positives with `--exclusions`, and only then move to `block`.

| Option | Value | What it does | Default | Required |
|---|---|---|---|---|
| `--listen` | `<addr:port>` | Where to accept connections | None | Required |
| `--upstream` | `<host:port>` | The web server behind the WAF | None | Required |
| `--log-dir` | `<path>` | The folder that holds `waf.jsonl`. One line per request; no query values, header values, cookies or bodies | None | Required |
| `--mode` | `off`, `detect` or `block` | `off` forwards without judging, `detect` judges and logs, `block` also answers 403 | `detect` | Optional |
| `--paranoia` | 1 to 4 | A higher level turns on more rules: fewer misses, more false positives | 1 | Optional |
| `--threshold` | number | The total score at which a request counts as an attack | 5 | Optional |
| `--max-body` | bytes | The largest request body accepted (413 above it) | 10485760 | Optional |
| `--max-body-inspect` | bytes | How much of a body is judged. The rest is forwarded unread and `body_truncated` is logged | 131072 | Optional |
| `--max-conns` | number | The most connections served at once (503 above it) | 512 | Optional |
| `--max-tracked-ips` | number | The most addresses remembered for rate limits and bans. The oldest are dropped first | 65536 | Optional |
| `--rate` | `<count>/<seconds>` | A limit per source address (429 with `Retry-After` above it) | None | Optional |
| `--ban-after` | number | How many refusals within a minute earn a ban. 0 means no bans | 0 | Optional |
| `--ban-ttl` | seconds | How long a ban lasts | 600 | Optional |
| `--rules` | `<path>` | Your own rules, one JSON object per line (`id`, `target`, `pattern`, `severity`, `paranoia`, `message`). A rule with a built-in's `id` replaces it | None | Optional |
| `--exclusions` | `<path>` | One JSON object per line (`rule`, `path_prefix`, optionally `target` and `method`) that switches a rule off for one place | None | Optional |
| `--allow-ip` | `<path>` | Sources forwarded without judging or rate limiting (addresses and CIDR) | None | Optional |
| `--deny-ip` | `<path>` | Sources that always get 403 | None | Optional |
| `--trust-forwarded-from` | `<path>` | Fronts whose `X-Forwarded-For` is believed. The address used is the first one from the right that is not itself trusted | None | Optional |

The rules, the exclusions and the three address files are read again while it runs.
A file that cannot be read later leaves the previous content in use.
A file named on the command line that cannot be read at start stops the start.

### waf-test: check your rules against sample requests

Each line of the corpus is one JSON object: `method`, `path`, optionally `query`, `headers` (an object) and `body`, and `expect` (`pass` or `block`).
It prints each line judged differently from `expect` as `file:line`, and exits 1 if there is any.
The corpora this project is tested with are in `tests/waf/`.

| Option | Value | What it does | Default | Required |
|---|---|---|---|---|
| `--corpus` | `<path>` | The file of sample requests | None | Required |
| `--rules` | `<path>` | Your own rules, as for `waf` | None | Optional |
| `--exclusions` | `<path>` | Exclusions, as for `waf` | None | Optional |
| `--paranoia` | 1 to 4 | As for `waf` | 1 | Optional |
| `--threshold` | number | As for `waf` | 5 | Optional |

### waf-report: read the audit log

| Option | Value | What it does | Default | Required |
|---|---|---|---|---|
| `--log-dir` | `<path>` | The folder that holds `waf.jsonl` | None | Required |
| `--since` | `YYYY-MM-DD` | Leave out lines before this day | None | Optional |

### The IPS policy file (`block --ips-policy`)

One JSON object per line. The first line whose conditions all hold decides; a line that cannot be read is skipped and counted, and a policy with no readable line is refused. Conditions: `sid` (a number or `"low-high"`), `classtype` and `category` (both compare with the classification text Suricata prints in `alert.category`), `severity_max`, `src` and `dst` (address or CIDR), `proto`, `dst_port`. Actions: `drop` (with `ttl` seconds), `alert` (record only), `ignore` (no record), `escalate` (needs `count`, `window` and `ttl`: stops the destination when the same source, destination and signature alert `count` times within `window` seconds; until then it only records).

```
{"sid":2001219,"action":"ignore"}
{"classtype":"A Network Trojan was detected","action":"drop","ttl":900}
{"sid":"2210000-2210050","action":"escalate","count":5,"window":60,"ttl":300}
```

The events are written to `ips.jsonl` in the log folder (`drop`, `observed`, `ignored` is not written, `protected`, `escalated`, `evicted`, `restored`, `stale`, `recovered`, `skipped`). Signature text and traffic content are never written. Change the policy file while `block` runs and it is reread within a second; an unreadable file keeps the previous policy.

### ips-test: check a policy against sample alerts

| Option | Value | What it does | Default | Required |
|---|---|---|---|---|
| `--policy` | `<path>` | The policy file | None | Required |
| `--alerts` | `<path>` | A file of Suricata alert lines (other lines are skipped) | None | Required |
| `--expect` | `<path>` | One `{"event":"drop"}` line per alert; a difference is printed as `file:line` and the exit code is 1 | None | Optional |
| `--never` | `<path>` | As for `block` | None | Optional |
| `--allow-private` | no value | As `--ips-allow-private` | Off | Optional |
| `--default` | `drop`, `alert` or `ignore` | As `--ips-default` | `alert` | Optional |
| `--ttl` | seconds | The stop time of a `drop` without its own `ttl` | 600 | Optional |

### ips-report: read the audit log

| Option | Value | What it does | Default | Required |
|---|---|---|---|---|
| `--log-dir` | `<path>` | The folder that holds `ips.jsonl` | None | Required |
| `--since` | `YYYY-MM-DD` | Leave out lines before this day | None | Optional |

### webapp: the browser console

A screen in the browser for editing the IPS, IDS, WAF and antivirus settings.
Every save is checked by the tool's own parsers. A file with an unreadable line is not saved; the line numbers come back instead.
The tool itself never starts or stops the console.

The shortest way is three steps.

1. Build the screens: `cd webapp/ui && ./build.sh`
2. Build the server: `cd webapp && cargo build --release`
3. Start it and open `http://127.0.0.1:8088/`: `webapp/target/release/packetdeath-webapp --data <dir> --config <dir> --logs <dir> --static webapp/ui/dist`

The first screen registers the first administrator.
A password is 128 characters or more. The password Chrome suggests is 15 characters, so it falls short. The "Generate a 128-character password" button on the registration screen draws 128 characters and hands them to the browser's password manager.

| option | value | what it does | default | required |
|---|---|---|---|---|
| `--data` | `<dir>` | where `users.json` and `webapp.jsonl` live | none | yes |
| `--config` | `<dir>` | where the editable settings and their generations (`backups/`) live | none | yes |
| `--logs` | `<dir>` | where `waf.jsonl` and `ips.jsonl` are read | none | yes |
| `--static` | `<dir>` | the screen files (`webapp/ui/dist/`) | none | no |
| `--listen` | `<addr:port>` | the address to listen on | `127.0.0.1:8088` | no |
| `--allow-remote` | none | allow listening on something other than `127.0.0.1` | not allowed | no |
| `--secure` | none | put `Secure` on the cookie (behind TLS) | off | no |
| `--rp-id` `--origin` | name and URL | turn passkeys on. `--origin` must match the browser's URL exactly. Passkeys work only on HTTPS or localhost | off | no (together) |
| `--second-factor-optional` | none | let operators and administrators change settings without a second factor | a second factor is required | no |

Sign-in asks for a second factor after the password: the 6-digit code of an authenticator app (scan the QR code on the settings screen), one of 10 one-time recovery codes, or a passkey.
Operators and administrators cannot change settings until a second factor is on.
The console has no TLS of its own. To use it from outside, put it behind a reverse proxy that ends TLS and add `--allow-remote` and `--secure`.

Copy the baseline rules (`webapp/deploy/baseline/`) into the `--config` folder and the IPS drops severity 1, drops severity 2 after 10 alerts in 60 seconds for 900 seconds, and never drops a public DNS resolver. The WAF keeps its 44 built-in rules and reads the console's files. The copy steps and the way back are in `webapp/docs/operations.ja.md` (in Japanese).

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
The meaning of every command and option is in the previous section, "Commands and options".

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
ThreatFox and URLhaus are for users authenticated at abuse.ch, so when the `--auth <key file>` file is missing, its mode is looser than `0600`, or the key is not 40 to 64 hex digits, no request is sent to them.
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
Put the key in a file that holds the single line `header = "Auth-Key: <your key>"`, set its mode to `0600`, and pass it with `--auth`.
abuse.ch puts the key inside the download address.
The script hands that address to curl on its standard input, so the key appears neither in `ps` nor in a log.
If the key file is missing, its mode is too loose, or the key has the wrong shape, the script sends no request at all to these two feeds.
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

The pktmon cleanup (`pktmon stop`, `pktmon filter remove`, `pktmon status`, deleting the captured files) and the removal of the service are in steps 8 and 9 of method C in "Using it on Windows".
The service installs no extra driver.
Automatic start after a reboot has not been tested on a real run (NOT VERIFIED).
That the service cuts a connection has not been confirmed (PW-7 did not pass).

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
- `webapp/docs/design.ja.md` and `webapp/docs/operations.ja.md`: the console's design with acceptance IDs PK-190 to PK-216, and how to run it (in Japanese). `webapp/docs/open-decisions.ja.md` lists the decisions still open and what holds each one.
- `docs/mitm-runbook.md`: the operating procedure for content inspection (in Japanese).
- `blocklists/README.md`: where the bundled blocklist came from, and what must never be added to it.
- `allowlists/README.md`: where the bundled allowlists came from, and their counts.

## License

The package declares `MIT OR Apache-2.0` in `Cargo.toml`.
Suricata and ClamAV are GPLv2; packetdeath uses them as separate processes and does not link to them.
`scripts/clamav-2g.patch` and `scripts/clamav-64/` are patches to ClamAV's source.
These two follow ClamAV's license (GPLv2), and the `MIT OR Apache-2.0` of the package does not extend to them.
The license of each bundled list follows its source (see the table above).
