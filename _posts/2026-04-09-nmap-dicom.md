---
layout: post
title: "DICOM Security 101: Network Security with Nmap"
description: "DICOM Security 101: network-level attack surface, what Nmap's DICOM scripts actually do, and a walkthrough of my fingerprinting PR."
tags: [dicom, medical-devices, nmap]
mermaid: true
---

Most people don't know that Nmap (the port scanning tool everyone and their grandma has used) supports DICOM. And not in a half-baked way: there are Nmap scripts revealing network protocol-level insights. So this post gives you some basic protocol fluency, review overall network attack surface with existing Nmap DICOM support, cover two Nmap DICOM PRs — vendor/version fingerprinting and capability enumeration, and touch briefly on my Scapy DICOM PR.

First **read the title.** This is network protocol only. DICOM file security stuff is in the [102]({% post_url 2026-04-16-dicom-file-format-security %}). So if you get the urge to "you forgot about", please read that article first.

## The Wire: Ports, Services, and Auth

Before the Nmap tour, let's talk about different flavors of networked DICOM.

### Flavors of DICOM

| Service | Port(s) |
| --- | --- |
| DICOM (upper-layer protocol) | 104, 11112 |
| DICOM over TLS | 2762 |
| DICOMweb | 80, 443 |

DICOMweb (WADO/QIDO/STOW) rides HTTPS, so on paper auth is in a better place: bearer tokens, OAuth, standard TLS, all the REST-API hygiene the upper-layer protocol never had. In practice, deployments ship with no auth or vendor default credentials, and the attack surface collapses into "under-configured REST API with PHI behind it." No Nmap NSE scripts exist for DICOMweb yet; it's out of scope for this post, but flagged as open tooling work.

### DIMSE Services

After association, DIMSE (DICOM Message Service Element) splits into two families. **C-services** (Composite) act on clinical objects themselves: store, find, get, move. This is the data plane, where PHI lives and where nearly all pentest and threat-model attention goes. **N-services** (Normalized) act on workflow state: MPPS (Modality Performed Procedure Step) updates, storage-commitment results, print jobs.

N-services get far less scrutiny. Once a peer is associated there's no per-verb auth, so an `N-SET` that flips an MPPS to COMPLETED or a forged storage-commitment `N-EVENT-REPORT` lands with the same trust as a `C-STORE`. No pixels touched, no hash mismatch, just corrupted workflow. The ones you need to know:

| Service | Why a pentester cares |
| --- | --- |
| `C-ECHO` | Protocol ping. Sent over an established A-ASSOCIATE, the step Nmap's `dicom-ping` skips. |
| `C-STORE` | Upload DICOM objects to the peer. Entry point for file-format fuzzing. |
| `C-FIND` | Query: patient lists, studies, series, Modality Worklist. PHI exposure or authorization-scoping check. |
| `C-MOVE` | Client names a destination AE Title (Application Entity Title); server opens a new A-ASSOCIATE there and C-STOREs the objects to it. SSRF-adjacent pivot primitive. |
| `C-GET` | Server returns objects over the current association — no second outbound connection, so not a pivot. Rare because it needs reverse-role negotiation for Storage SOP (Service-Object Pair) classes; try when `C-MOVE` is blocked. |
| **N-services** (`N-CREATE`, `N-SET`, `N-ACTION`, `N-EVENT-REPORT`, `N-GET`) | Workflow/event verbs: MPPS state, Storage Commitment receipts, Print. No pixel data, so audit rules and threat models routinely skip them. |

## Auth in DICOM

A-ASSOCIATE layers two authorization controls, none of which prove identity. The server decides: can this peer connect, and what operations is the association allowed to perform.

| Control | What it authorizes | Granularity | Typical failure |
| --- | --- | --- | --- |
| Called AE Title (fixed header) | *Whether you can ask* — is the association accepted at all | Per-peer | `ANY-SCP` wildcard accepts any caller |
| Abstract Syntax / SOP Class UID (item 0x20 proposed → 0x21 accepted) | *What you can ask* — which operation classes (Storage, Q/R, MWL (Modality Worklist), MPPS, Print) | Per-operation-class | Storage accepted when the role only needs Query |

The table leaves out something important: an AE Title is a plain string in a packet header. It is the only identifier classic DICOM assigns to a device, and nothing in the protocol ties that string to a specific IP address. C-MOVE makes this consequential. The destination AE Title in a C-MOVE-RQ is a name the server looks up in its own table (AET to IP:port), then opens a new outbound connection to wherever that entry points. Name an AE Title the PACS (Picture Archiving and Communication System) already trusts and it will ship PHI to wherever that entry maps. One physical device typically registers several AETs (Storage, Storage Commitment, MPPS, MWL client), each scoped separately in the PACS config. Naming conventions like `MR_ER_3` or `WORKLIST_PROD` are predictable enough that wordlists work, which is why `dicom-brute` exists.

Authentication is a separate conversation from the gates above. For network authentication, DICOM supports two mechanisms:

- **DICOM TLS** — authenticates the transport peer. Mutual-auth capable.
- **User Identity Negotiation** — authenticates the user. [DICOM PS3.7 §D.3.3.7](https://dicom.nema.org/medical/dicom/current/output/html/part07.html) defines a User Identity sub-item (Type `0x58`) that rides inside the A-ASSOCIATE-RQ and supports one of:
    - username only
    - username + passcode
    - Kerberos service ticket
    - SAML assertion
    - JSON Web Token (JWT)

The catch: **there's no Reason code unique to credential failure**. Per [PS3.7 §D.3.3.7.3](https://dicom.nema.org/medical/dicom/current/output/chtml/part07/sect_D.3.3.7.3.html), a spec-compliant acceptor rejects user identity with Result = `1` (rejected-permanent), Source = `2` (service-provider, ACSE (Association Control Service Element)), Reason = `1` (no-reason-given). That's `1/2/1`. The Source byte separates it from an AE Title miss, which comes back as Source = `1` (service-user): either `1/1/7` (explicit) or the flattened `1/1/1`. Read Source first. On stacks that flatten everything to `1/1/1`, the only tell left is whether your RQ carried a `0x58` sub-item.

### TLS: Specified, Inconsistently Deployed

[PS3.15](https://dicom.nema.org/medical/dicom/current/output/html/part15.html) defines TLS profiles with mutual auth. The spec is fine. The deployments are not.

There's no STARTTLS-style upgrade in A-ASSOCIATE and no in-band signal that a peer requires TLS. A listener on 104 either speaks DICOM in the clear or it speaks TLS, and you find out by probing. Port 2762 is `dicom-tls` per IANA, but plenty of deployments run TLS on 104 or 11112 because the vendor's config UI has one "DICOM port" field and a "use TLS" checkbox.

So integrators bolt encryption on at layers they understand. Four patterns, only the last is actual DICOM TLS:

1. **DICOMweb behind an API gateway.** Google Cloud Healthcare API, AWS HealthImaging, Azure DICOM Service, and modern teleradiology SaaS platforms all ship this: DICOM verbs over HTTPS with OAuth at the edge. When DICOM crosses the WAN, this is the wire it crosses on.
2. **Site-to-site VPN with plain DIMSE inside.** Teleradiology classic. The "TLS" is the VPN; the DICOM payload on the inside hop is plaintext. Pop the reading center — often a Windows box in a strip mall under a radiologist's desk — and you have unauthenticated DIMSE to the hospital PACS, AE Title gate notwithstanding.
3. **Image exchange networks.** Nuance PowerShare, Life Image, Intelerad/Ambra. Managed DICOMweb gateways with a sales team.
4. **Actual DICOM TLS on 2762 or TLS-wrapped 11112.** Rare, and almost always inside a single health system rather than between organizations.

Whatever the envelope, the inner DIMSE is still gated by the same Called AE Title check from the previous section. The transport got authenticated. The DICOM verbs didn't. Mutual TLS, where it shows up, usually rides a flat hospital-wide CA: every modality's cert trusted to act as every other, revocation never configured. More commonly it's server-auth only, with the AE Title standing in as "client identity," which is not authentication.

## What Nmap Already Does for DICOM

With the auth model in hand, here's what Nmap already ships to probe it. Two DICOM-aware NSE scripts, both Paulino Calderon's 2019 work [[1]](#references): `dicom-ping` (discovery) and `dicom-brute` (AE Title brute-force), riding the `dicom` NSE library he also wrote. My PRs build on that surface: fingerprinting reads bytes that already come back in the AC, and capability enumeration proposes a richer Presentation Context list to map what the SCP (Service Class Provider) will accept. The `dicom-ping` loose ends are a separate diff.

### 1. Port Scanning

```bash
nmap -sS -p 104 <target>
```

Without any NSE scripts, you can tell if DICOM-related ports are open. Port 104 is the standard DICOM port. But let's be honest, knowing a port is open tells you almost nothing. It's like confirming a building has a door. Congratulations.

### 2. DICOM Discovery (dicom-ping)

```bash
nmap -sC -p 104 <target>
```

With Nmap's default scripts enabled (`-sC`), the `dicom-ping` script runs automatically. `-A` will also pull it in, but `-A` is `-sC` plus OS detection, version detection, and traceroute, which could be more than you want to throw at a hospital network. For DICOM recon specifically, starting at the targeted `-sC -p 104` is best. Either way, here's the thing: this "ping" is not a real DICOM ping because it never sends a C-ECHO. It only does the first half, the A-ASSOCIATE request/response handshake. That's it.

A typical run looks like this:

```
PORT     STATE SERVICE REASON
4242/tcp open  dicom   syn-ack
| dicom-ping:
|   dicom: DICOM Service Provider discovered!
|_  config: Called AET check enabled
```

A successful association (AE accepted) or even a rejected (A-ASSOCIATE-RJ) one is enough for Nmap to report. So the script sees the server speak DICOM and calls it a day. No full C-ECHO, no verification of actual DICOM service capability. Just the associate handshake.

#### How This Works

Since everything Nmap does for DICOM (discovery, "insecure AE Title" detection, brute force, and the vendor/version fingerprinting I'll get to below) rides on this same A-ASSOCIATE exchange, it's worth pausing on the actual wire flow before going further.

{% raw %}
<div class="mermaid">
sequenceDiagram
    autonumber
    participant C as Client (Nmap)
    participant S as Server (PACS)

    rect rgba(180, 180, 100, 0.25)
    Note over C,S: Ping Phase 1: Association
    C->>S: A-ASSOCIATE-RQ (0x01)<br/>Calling AE: "NMAP_DICOM_PING"
    alt Server accepts
        S-->>C: A-ASSOCIATE-AC (0x02)<br/>e.g. "Implementation: DCMTK 3.6.9"
    else Server rejects
        S-->>C: A-ASSOCIATE-RJ (0x03)<br/>Result / Source / Reason in header
    end
    Note over C: Parse Vendor/Version<br/>Check AE Title<br/>Drop Connection
    C-xS: [Connection Terminated]
    end

    rect rgba(200, 80, 80, 0.25)
    Note over C,S: SKIPPED: Ping Phase 2 (C-ECHO)
    C--xS: C-ECHO-RQ (Data 0x04)
    S--xC: C-ECHO-RSP (Data 0x04)
    C--xS: A-RELEASE-RQ (0x05)
    end
</div>
{% endraw %}

Nmap sends an A-ASSOCIATE-RQ, the server responds with an A-ASSOCIATE-AC (accept) or A-ASSOCIATE-RJ (reject), and Nmap drops the connection. Nmap DICOM scripts are built on parsing whatever comes back in that single response: no extra packets, no extra noise on the network. Keep this mental model.

One script-specific note: when `dicom-ping` gets an association accepted using the generic `ANY-SCP` called AE Title, it flags the wildcard as insecure. The server is treating that wildcard identifier as a valid peer, so the Called AE Title check isn't filtering anything.

### 3. AE Title Brute Force

```bash
nmap --script dicom-brute <target>
# With a custom wordlist:
nmap --script dicom-brute --script-args dicom-brute.aets=aets.txt <target>
```

`dicom-brute` is categorized under `auth` and `brute`, not `default`, so `-sC` won't pull it in. You have to call it explicitly. The most important script argument here is `dicom-brute.aets`, which lets you specify a wordlist for guessing the called AE Title.

If `dicom-ping` came back rejected, or came back accepted under `ANY-SCP` and you want to enumerate real AETs, this is your next move. Feed it a list of common AE Titles and see what sticks.

#### What the Reject Tells You

When the server sends A-ASSOCIATE-RJ instead of AC, [PS3.8 §9.3.4](https://dicom.nema.org/medical/dicom/current/output/html/part08.html) defines the `(Result, Source, Reason)` triple in the reject PDU (Protocol Data Unit). Decode it:

| Result / Source / Reason | What likely happened | Pentester move |
| --- | --- | --- |
| 1 / 1 / 1 (rejected permanent, service-user, no reason given) | AE Title miss. On stacks that flatten credential rejections into this code (rather than the spec-compliant `1/2/1`), it can also mean a credential miss. **Without** a `0x58` sub-item in your RQ, assume AE Title; **with** a `0x58`, could be either. | Try an AE Title wordlist first; once you've pinned a valid AET, re-run *with* a `0x58` and pivot to a credential wordlist. |
| 1 / 1 / 7 (called AET not recognized) | AE Title gate, explicit | Brute AE Title |
| 1 / 2 / 1 (rejected permanent, service-provider/ACSE, no reason given) | Spec-compliant credential miss per [PS3.7 §D.3.3.7.3](https://dicom.nema.org/medical/dicom/current/output/chtml/part07/sect_D.3.3.7.3.html). AE Title was accepted, user identity was not. | Keep the AET, brute `0x58` credential forms. |

Order of operations: on spec-compliant stacks the Source byte alone separates the two gates (`1/1/*` = AE Title, `1/2/*` = user identity), so you can run the campaigns independently. On stacks that flatten everything to `1/1/1`, the code means different things depending on whether your RQ carried a `0x58`. (`1/1/2 protocol version not supported` also exists, rare in practice; flip the Protocol-Version bits and re-propose if you hit it.)

The AC tells you who built the stack, the RJ tells you which gate you tripped on. Once you're past both gates, `dicom-enum` tells you what the stack will actually speak.

## Adding Vendor & Version Fingerprinting

I submitted a PR to Nmap to add basic DICOM vendor and version detection [[2]](#references). Seems boring on the surface, but it's core to what Nmap does: fingerprinting. Default tooling should ship with first-class identification of what stack you're talking to. Nmap's didn't, so I wrote it.

Who knows when the PR gets merged, so I'm writing about it now.

### What dicom-ping Leaves on the Table

After looking at the DICOM A-ASSOCIATE packets that Nmap's `dicom-ping` script already exchanges, I noticed something useful: the A-ASSOCIATE-AC (accept) response contains reliable vendor and version information just sitting there. No extra packets.

{% include associate_ac_pdu.html %}

Each Item Type `0x21` is the server's commitment to one **Presentation Context** from the RQ's proposals: a Presentation Context ID paired with exactly one Accepted Transfer Syntax (sub-item `0x40`) for a given Abstract Syntax (SOP Class UID: Verification, Storage, Query/Retrieve, Modality Worklist). The accepted IDs gate every DIMSE op that follows: propose Storage and get it accepted, you can C-STORE; don't propose it, or get it rejected, and you can't. That per-encoding negotiation is itself an attack primitive — *how* you can ask, beyond the two auth gates above. Downgrade to Implicit VR to strip type information, force uncompressed to dodge codec paths, or pick a rare JPEG variant to steer the peer onto its dustiest decoder. Servers that accept obsolete or rare syntaxes by default hand you the lever for free.

The A-ASSOCIATE-AC packet also has a User Information payload (Item Type `0x50`) containing nested Type-Length-Value (TLV) structures. The two fields the PR fingerprints:

- **`0x52` Implementation Class UID** — a dot-notation OID (Object Identifier), mandatory in the AC. The DICOM spec says UIDs "shall not be parsed", but in practice the root arc identifies the implementer: [`1.2.276.0.7230010.3`](https://oid-base.com/get/1.2.276.0.7230010.3) is OFFIS DCMTK (a software library); [`1.2.840.113619`](https://oid-base.com/get/1.2.840.113619) is GE Medical Systems (an OEM).
- **`0x55` Implementation Version Name** — a free-form string, optional. `OFFIS_DCMTK_369` parses to DCMTK 3.6.9 [[3]](#references). Conforming implementations can omit it, and the PR handles that case.

#### Why You Need to Look Up Both

In theory `0x52` is the authoritative vendor identifier, the medical device manufacturer (MDM) implementing the DICOM stack. In practice, a lot of lazy MDMs ship devices with a third-party stack's UID (DCMTK, dcm4che, pynetdicom) and never override it. So `0x52` would happily report "OFFIS" on a device that's actually a Brand X modality with DCMTK linked in. You can't trust either field in isolation.

From a pentester's point of view, `0x55` is probably the most important. The Version Name tends to track the software that's actually on the wire, parsing PDUs. That's the majority of the attack surface: which library's bugs you get, regardless of whose product.

The PR does pattern-match table lookups on **both** fields independently. The 0x52 path runs the UID against two OID tables, one for software toolkits and one for OEMs, so the result tags which side it came from:

```lua
local TOOLKIT_UID_PATTERNS = {
  {"^1%.3%.6%.1%.4%.1%.25403%.",                  "ClearCanvas"},
  {"^1%.2%.826%.0%.1%.3680043%.9%.3811%.",        "pynetdicom"},
  {"^1%.2%.826%.0%.1%.3680043%.8%.641%.",         "Orthanc"},
  {"^1%.2%.826%.0%.1%.3680043%.8%.1057%.",        "OsiriX/Horos"},
  {"^1%.2%.276%.0%.7230010%.3%.",                 "DCMTK"},
  {"^1%.2%.40%.0%.13%.1%.3",                      "dcm4che"},
}

local MANUFACTURER_UID_PATTERNS = {
  {"^1%.2%.840%.113619%.",                        "GE Healthcare"},
  {"^1%.3%.12%.2%.1107%.",                        "Siemens"},
  {"^1%.2%.840%.113704%.",                        "Philips"},
  {"^1%.3%.46%.670589%.",                         "Philips"},
  {"^1%.2%.840%.114257%.",                        "Agfa"},
  {"^1%.2%.392%.200036%.",                        "Fujifilm"},
}
```

The 0x55 path uses a similar table keyed on substrings of the version string. Surfacing what each field says lets you compare:

- If `0x52` and `0x55` disagree, that's a useful signal: an OEM customized the stack, and you should look up the OID to find who.
- If both fields point at the same open-source stack, the manufacturer probably never registered their own OID.

## Capability Enumeration (dicom-enum)

Knowing the box is Orthanc 1.11.0 isn't enough. The next questions are: what role does it play on the network (image archive, work-order server, scanner, print gateway), and which kinds of objects will it accept from a peer? Both answers are sitting in the A-ASSOCIATE-AC if you ask the right thing. So I wrote [`dicom-enum`](https://github.com/tmart234/nmap_dicom/blob/main/scripts/dicom-enum.nse), a third NSE script that proposes about thirty Presentation Contexts in one A-ASSOCIATE-RQ and parses what came back per context.

The AC returns one of five result codes per Presentation Context per [PS3.8 §9.3.3.2](https://dicom.nema.org/medical/dicom/current/output/html/part08.html): accepted, user-rejection, abstract-syntax-not-supported, transfer-syntaxes-not-supported, no-reason. The script buckets them. What lands in `accepted` is what the server will process on the next DIMSE op.

```
| dicom-enum:
|   association: accepted (max_pdu=16384, vendor=Orthanc 1.11.0)
|   service_classes:
|     QR-Patient-Root
|     QR-Study-Root
|     Storage
|     Verification
|   inferred_device_class: Archive front-end
|   results:
|     accepted:
|       count: 15
|       items:
|         CT Image Storage - Explicit VR Little Endian
|         MR Image Storage - JPEG 2000 Image Compression (Lossless Only)
|         Encapsulated PDF Storage - Explicit VR Little Endian
|     abstract-syntax-not-supported:
|       count: 10
|       items:
|         Modality Worklist Information Model - FIND
```

Each line in `accepted` pairs an object type with an encoding. The DICOM standard defines a separate Storage class for every kind of object it carries: CT images, MRs, ultrasounds, mammograms, encapsulated PDFs, structured reports, RT plans, presentation states, and several dozen more. A properly scoped SCP only accepts the types it has reason to see, so a CT-facing endpoint that also accepts encapsulated PDFs is a misconfiguration worth noting. The accepted list is also the menu of file structures the server's parser will receive on the next C-STORE, which is the bridge to [102]({% post_url 2026-04-16-dicom-file-format-security %}).

The `inferred_device_class` line is the other half. The mapping isn't anything the spec defines (it's practitioner shorthand), but it tracks real roles in a hospital. Three patterns show up most:

- **The work-order box.** Serves Modality Worklist, won't accept Storage. This is the radiology information system or its DICOM gateway: the box that tells scanners which studies they're scheduled to acquire today, with patient names, MRNs, and scheduled procedure codes attached. No images live here.
- **The archive.** Accepts Storage from upstream, serves Query/Retrieve to downstream readers, doesn't speak Worklist. PACS, VNA, research archive. The studies and their long-term retention live here.
- **The scanner.** Only proposes Storage as a client, no Query/Retrieve, no Worklist. The CT, MR, or ultrasound itself, pushing acquired studies to whatever's configured to receive them.

Which one you're looking at changes the threat model and the next recon move. The work-order box has demographics and scheduling but no pixels; the archive has the pixels and a retention policy that probably says "forever"; the scanner has neither but is where the acquisition itself happens (and is usually the box running the oldest, most loosely-patched software on the network). "PACS" by itself doesn't get you any of that.

`dicom-enum` is in the `discovery` and `safe` categories, not `brute` and not `default`. PACS networks tend to be running brittle modalities and vendor support contracts that get unhappy about unsolicited associations, and a default-category script proposing thirty Presentation Contexts at every open port would land in the wrong inbox.

The recon flow, start to finish:

```bash
nmap -sC -p 104,11112,2762,4242 <target>           # ping + vendor/version
nmap --script dicom-brute <target>                  # if the AET gate rejects
nmap --script dicom-enum \
     --script-args dicom.called_aet=<AET> <target>  # capability map
```

## Beyond Nmap (Scapy)

The A-ASSOCIATE-RQ sent by the client carries the same `0x50` User Information structure, optionally including the User Identity sub-item covered earlier. Even after a successful association, some implementations scope DIMSE-level authorization by AE Title or User Identity credentials, so "associated" doesn't always mean "full access."

This is where my [Scapy DICOM contrib module](https://github.com/secdev/scapy/commit/ded1d73d7c779099964338803ad7b366c99d6820) comes in. Once Nmap tells you who or what you're talking to, you can use Scapy to send a C-FIND, or craft a malformed image PDU to test a parser. I'll cover that workflow in a future post.

As a taste, here's what the Scapy packet format looks like when crafting an A-ASSOCIATE-RQ that carries username and passcode:

```python
DICOM()/A_ASSOCIATE_RQ(calling_ae_title="PENTEST", called_ae_title="ANY-SCP",
    variable_items=[DICOMUserIdentity(user_identity_type=2,
        primary_field=b"admin", secondary_field=b"password")])
```
Similar to the AE title brute force, we can hook username and password variables to cycle through any standard or custom wordlists (e.g., the SecLists medical-devices wordlist).

## References

1. Calderon, P. (2019). *New NSE library for DICOM and scripts `dicom-ping` and `dicom-brute`.* nmap-dev mailing list announcement: [seclists.org/nmap-dev/2019/q3/6](https://seclists.org/nmap-dev/2019/q3/6). Script docs: [`dicom-ping`](https://nmap.org/nsedoc/scripts/dicom-ping.html), [`dicom-brute`](https://nmap.org/nsedoc/scripts/dicom-brute.html).
2. Nmap PR adding DICOM vendor/version fingerprinting off the A-ASSOCIATE-AC (link TBD pending merge or reviewable state).
3. OFFIS DCMTK 3.6.9 release announcement (Dec 10, 2024): [forum.dcmtk.org/viewtopic.php?t=5429](https://forum.dcmtk.org/viewtopic.php?t=5429).
