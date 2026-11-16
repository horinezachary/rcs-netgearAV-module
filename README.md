# Netgear AV Switches

A [Rack Control Surface](https://github.horinetech.com/rcs-releases/) module that finds, watches and
manages Netgear AV Line switches (M4250, M4300, M4350 and M4500) through each switch's own REST API.
It needs no controller: every switch is talked to directly. Switches onboarded to NETGEAR Engage work
too (see [Engage](#netgear-engage)).

- **Switches**: every switch at a glance: ports up, PoE draw against budget, CPU, temperature,
  firmware, uptime and live traffic. The Stream Deck shows one key per switch; press it for its ports.
- **Ports**: the front panel as it looks on the switch, odd ports on top and even ports below,
  coloured by access VLAN, with link speed, PoE draw and what LLDP sees on the other end. Tap a port,
  pick its VLAN on keys 1 to 10, then hold SAVE (key 15). Hold key 13 to turn PoE on or off, key 14 to
  power cycle it. The screen has PoE, power cycle and shut down/enable buttons, each with a confirmation.
  The web view has the whole port table with a VLAN menu per port and an Apply button.
- **Discover**: switches on the unit's network, found by Netgear's discovery protocol (NSDP) or by a
  scan of the unit's subnets for the API port. Press a switch's key, or Add, to watch it.
- **Setup**: switches by address, the Allow changes switch, and in the web view the logins.

## The switches are the source of truth

Everything shown is read from the switches every few seconds and kept only in memory: nothing about
the network is saved. State holds which switch and port the panel shows; config holds the list of
switches (address, API port, pinned certificate, a name from discovery) and the Allow changes switch.
Starting, restoring a save, resuming after a power cut and reconnecting only read. The module changes a
switch only when someone sets a port VLAN, turns PoE on or off, power cycles a port, shuts down or
enables a port, or saves the running config, and only with **Allow changes** on in Setup (it is off by
default). After a change it shows what the switch then reports, never a guess.

Changes go to the switch's running config, as they do from the switch's own web page. They are live
at once but are lost at the next reboot until saved: the module marks a switch it changed as
**Not saved** and offers **Save to startup** (with a confirmation) until it is.

Logins are module secrets (host 0.14.0 or later): the controller keeps them apart from state and
config. Named saves include them, so restoring a save or loading it on another unit brings the logins
back. A downloaded save carries them only sealed with a passphrase you pick, or not at all. Module
Reset or a factory reset removes them. Earlier versions kept them in `credentials.json` in the data
folder; the first start after updating moves them into the secrets. The web view can show a stored
password after the system PIN is entered at the panel (a browser signed in with the PIN is not asked
again), and only to the browser that asked.

## NETGEAR Engage

Engage is a desktop app with no API other software can use, so the module does not talk to it. It
does not need to: Engage manages each switch through the same switch, and replaces the switch's admin
password with the Engage **site password** when it onboards it. Set that once as the **shared login**
(user `admin`) and every switch Engage manages connects with it. A switch with a different password
gets its own login in Setup. Engage finds switches in the same broadcast domain, as the module's
Search does; switches on routed VLANs are added by address in both.

## Certificates

The switches serve their API over self-signed certificates. The module trusts the certificate it sees
on the first connection and stores its SHA-256 fingerprint in config. Each request checks the
fingerprint before sending anything, so a password never goes to a different device. If the
certificate changes (a replaced switch, a new certificate), the module stops reading that switch and
Setup shows **Trust new certificate**.

## Discovery

**Search** broadcasts an NSDP read request (UDP 63322 and 63324; answers come back on 63321 and 63323),
as the Netgear Switch Discovery Tool does, and lists model, name, MAC, address and firmware. It opens
by itself when Discover opens. Whether every AV Line firmware answers NSDP has not been checked on
hardware yet, so **Scan subnet** also tries every address on the unit's own subnets (each /22 or
smaller) for a TLS answer on port 8443. The scan only completes a TLS handshake: it sends no request
and no login.

## Develop

Node.js 22 or later, and a checkout of the main `rack-control-surface` repo, which holds the SDK
until it is published to npm.

```sh
# next to this folder: git clone …/rack-control-surface && cd rack-control-surface && npm install && npm run build
npm install            # links the SDK from ../rack-control-surface when it is there
npm run link-sdk -- C:\src\rack-control-surface    # or point at a checkout somewhere else (or set RCS_REPO)
npm test               # unit tests against mock switches and the SDK's fake controller
npm run mock           # three pretend switches on https://127.0.0.1:8443-8445, NSDP on udp 63322
RCS_NETGEAR_SCAN=127.0.0.1:8443,127.0.0.1:8444,127.0.0.1:8445 RCS_NETGEAR_NSDP=127.0.0.1:63322 npm run dev
```

In the simulator's web view (http://127.0.0.1:5174), open Netgear AV Switches › Setup and set the
shared login `admin` / `password1`, then add the switches on Discover (or by address and port in Setup).
`npm ci` clears `node_modules`, so run `npm run link-sdk` again after it. The two `RCS_NETGEAR_*`
variables point Discover at the mock instead of the real network.

Anything that changes live show equipment is developed against the mock first. Check with the owner
before pointing a development build at a production switch with Allow changes on.

### What it reads and writes

All on `https://<switch>:8443/api/v1/`, with the `Bearer` token from `POST login`:

| Request | When |
| --- | --- |
| `GET sw_portstats?portid=ALL`, `swcfg_poe?portid=ALL` | every 5 s |
| `GET device_info`, `swcfg_port`, `poe_config`, `lldp_remote_devices`, `fiber_optics`, `swcfg_vlan` | every 20 s (names of VLANs once) |
| `POST swcfg_vlan_membership`, `POST swcfg_port` (`portVlanId`) | operator sets a port's access VLAN |
| `POST swcfg_poe` (`enable`, or `reset` to power cycle) | operator changes PoE |
| `POST swcfg_port` (`adminMode`) | operator shuts down or enables a port |
| `POST config_copy?directive=rtos` | operator saves the running config |

Setting an access VLAN makes the port an untagged member of the new VLAN, sets it as the PVID, then
removes the port from the old VLAN if it was untagged there. Tagged VLANs on the port stay. Each write
sends back the whole record the switch reported with only the change applied, which the firmware
requires. Shapes follow Bitfocus Companion's
[netgear-avline](https://github.com/bitfocus/companion-module-netgear-avline) module and the
[m4300-site-report](https://github.com/njrc88-div/m4300-site-report) project, and are read tolerantly
since firmware differs. So far they have only been tested against the mock.

## Releasing

Every merge to `main` is a release (`.github/workflows/release.yml`), versioned from the PR title:
`feat:` is a minor bump, `!:` or `BREAKING CHANGE` a major one, anything else a patch; `[skip release]`
skips it. The workflow tests, stamps the version into `module.json`, packs, signs and publishes
`netgear-av-<version>.zip` and its `.sig` as a GitHub release here, where units find it through the
module index in [horinezachary/rcs-releases](https://github.com/horinezachary/rcs-releases).

It needs two Actions secrets:

- `RCS_SIGNING_KEY`: the module's private signing key, made with
  `node node_modules/@rcs/module-sdk/dist/pack-cli.js keygen`. Its public key is this module's entry
  in `index.json` in rcs-releases.
- `RCS_SOURCE_TOKEN`: a fine-grained token with Contents read-only on `rack-control-surface`, so the
  workflows can link the SDK from it. CI uses the tag in `package.json` `rcs.sdkRef`.

## Layout

| Path | What |
| --- | --- |
| `src/index.ts` | The module backend: views, keys, config, logins and the messages its UIs send |
| `src/client.ts` | The connection to one switch: login, polling, and the changes |
| `src/http.ts` | HTTPS with the certificate pinned before a request is sent |
| `src/model.ts` | Turning the API's records into ports, VLANs and switch health |
| `src/discovery.ts` | NSDP search and the API port scan |
| `src/mock.ts`, `src/mock-cli.ts` | Mock switches; their test certificates are in `test/fixtures` |
| `ui/index.html` | The panel UI: Switches, Ports, Discover, Setup |
| `web/index.html` | The web view's pages of the same names |
| `scripts/link-sdk.mjs` | Links `@rcs/*` from a main repo checkout |
