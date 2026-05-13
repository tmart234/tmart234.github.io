---
layout: post
title: "DICOM Security 101: Network Security with Nmap"
description: "DICOM Security 101: network-level attack surface, what Nmap's DICOM scripts actually do, and a walkthrough of my fingerprinting PR."
tags: [dicom, medical-devices, nmap]
mermaid: true
---

Most people don't know that Nmap (the port scanning tool everyone and their grandma has used) supports DICOM. And not in a half-baked way: there are Nmap scripts revealing network protocol-level insights. The A-ASSOCIATE-AC packet already leaks vendor, version, and accepted capabilities; Nmap just doesn't parse them. This post covers basic protocol fluency, what Nmap already ships, two PRs I submitted (fingerprinting and capability enumeration), and my Scapy DICOM PR.

This is network protocol only. DICOM file security stuff is in the [102]({% post_url 2026-04-16-dicom-file-format-security %}).

## The Wire: Ports, Services, and Auth

DICOM nodes act as clients (SCU) and servers (SCP). Two of them set up an A-ASSOCIATE — a TCP-level handshake that negotiates which operations the session will allow — before any DIMSE message moves. Everything in this post happens in or after that handshake.

### Flavors of DICOM

| Service | Port(s) |
| --- | --- |
| DICOM (upper-layer protocol) | 104, 11112 |
| DICOM over TLS | 2762 |
| DICOMweb | 80, 443 |

DICOMweb (WADO/QIDO/STOW) rides HTTPS, so on paper auth is in a better place: bearer tokens, OAuth, standard TLS, all the REST-API hygiene the upper-layer protocol never had. In practice, deployments ship with no auth or vendor default credentials, and the attack surface collapses into "under-configured REST API with PHI behind it." DICOMweb is out of scope for this post; the lack of Nmap coverage is in the gaps list at the end.

### DIMSE Services

After association, DIMSE (DICOM Message Service Element) splits into two families. **C-services** (Composite) act on clinical objects themselves: store, find, get, move. This is the data plane, where PHI lives and where nearly all pentest and threat-model attention goes. **N-services** (Normalized) act on workflow state: MPPS (Modality Performed Procedure Step) updates, storage-commitment results, print jobs.

N-services get far less scrutiny. Once a peer is associated there's no per-verb auth, so an `N-SET` that flips an MPPS to COMPLETED or a forged storage-commitment `N-EVENT-REPORT` lands with the same trust as a `C-STORE`. No pixels touched, no hash mismatch, just corrupted workflow. The ones you need to know:

| Service | Why a pentester cares |
| --- | --- |
| `C-ECHO` | Protocol ping. Sent over an established A-ASSOCIATE. |
| `C-STORE` | Upload DICOM objects to the peer. Entry point for file-format fuzzing. DICOMweb's `STOW-RS` is the modern equivalent ingress, inheriting the REST-API failure modes from above. |
| `C-FIND` | Query: patient lists, studies, series, Modality Worklist. PHI exposure or authorization-scoping check. |
| `C-MOVE` | Client names a destination AE Title (Application Entity Title); server opens a new A-ASSOCIATE there and C-STOREs the objects to it. SSRF-adjacent pivot primitive. |
| `C-GET` | Server returns objects over the current association: no second outbound connection, so not a pivot. Try when `C-MOVE` is blocked. |
| **N-services** (`N-CREATE`, `N-SET`, `N-ACTION`, `N-EVENT-REPORT`, `N-GET`) | Workflow/event verbs: MPPS state, Storage Commitment receipts, Print. No pixel data, so audit rules and threat models routinely skip them. |

## Auth in DICOM

A-ASSOCIATE layers two authorization controls, none of which prove identity. The server decides: can this peer connect, and what operations is the association allowed to perform.

| Control | What it authorizes | Granularity | Typical failure |
| --- | --- | --- | --- |
| Called AE Title | Whether you can ask — is the association accepted at all | Per-AET (one device may register several) | ANY-SCP wildcard accepts any caller |
| Abstract Syntax / SOP Class UID | *What you can ask*: which operation classes (Storage, Q/R, MWL (Modality Worklist), MPPS, Print) | Per-operation-class | Storage accepted when the role only needs Query |

The table leaves out something important: an AE Title is a plain string in a packet header. It is the only identifier classic DICOM assigns to a device, and nothing in the protocol ties that string to a specific IP address. C-MOVE makes this consequential. The destination AE Title in a C-MOVE-RQ is a name the server looks up in its own table (AET to IP:port), then opens a new outbound connection to wherever that entry points. Name an AE Title the PACS (Picture Archiving and Communication System) already trusts and it will ship PHI to wherever that entry maps. One physical device typically registers several AETs (Storage, Storage Commitment, MPPS, MWL client), each scoped separately in the PACS config. Naming conventions like `MR_ER_3` or `WORKLIST_PROD` are predictable enough that wordlists work, which is why `dicom-brute` exists.

One IP, many AETs. A 2004 AAPM physics report walking through DICOM connectivity at a real site notes a single CT advertising one AET as a Storage SCU and a different AET — `PR-ct5_SCU` — as a Print SCU [[4]](#references). That's the rule. So an AET wordlist hit isn't telling you the device's name; it's telling you one of the device's roles. Run `dicom-enum` against each hit and the capability map will differ per AET.

For network authentication, DICOM supports two mechanisms:

- **DICOM TLS** — authenticates the transport peer. Mutual-auth capable.
- **User Identity Negotiation** — authenticates the user. [DICOM PS3.7 §D.3.3.7](https://dicom.nema.org/medical/dicom/current/output/html/part07.html) defines a User Identity sub-item (Type `0x58`) that rides inside the A-ASSOCIATE-RQ and supports one of:
    - username only
    - username + passcode
    - Kerberos service ticket
    - SAML assertion
    - JSON Web Token (JWT)

The catch: **there's no Reason code unique to credential failure**. Per [PS3.7 §D.3.3.7.3](https://dicom.nema.org/medical/dicom/current/output/chtml/part07/sect_D.3.3.7.3.html), a spec-compliant acceptor rejects user identity with Result = `1` (rejected-permanent), Source = `2` (service-provider, ACSE (Association Control Service Element)), Reason = `1` (no-reason-given). That's `1/2/1`. The Source byte separates it from an AE Title miss, which comes back as Source = `1` (service-user): either `1/1/7` (explicit) or the flattened `1/1/1`. Read Source first. On stacks that flatten everything to `1/1/1`, the only tell left is whether your RQ carried a `0x58` sub-item.

None of this is authentication. It's a guest list with no bouncer.

### TLS: Specified, Inconsistently Deployed

[PS3.15](https://dicom.nema.org/medical/dicom/current/output/html/part15.html) defines TLS profiles with mutual auth. The spec is fine. The deployments are not.

There's no STARTTLS-style upgrade in A-ASSOCIATE and no in-band signal that a peer requires TLS. A listener on 104 either speaks DICOM in the clear or it speaks TLS, and you find out by probing. Port 2762 is `dicom-tls` per IANA, but plenty of deployments run TLS on 104 or 11112 because the vendor's config UI has one "DICOM port" field and a "use TLS" checkbox.

So integrators bolt encryption on at layers they understand. Four patterns, only the last is actual DICOM TLS:

1. **DICOMweb behind an API gateway.** Google Cloud Healthcare, AWS HealthImaging, Azure DICOM Service, modern teleradiology SaaS: DICOM verbs over HTTPS with OAuth at the edge.
2. **Site-to-site VPN with plain DIMSE inside.** Teleradiology classic. The "TLS" is the VPN; the inner DIMSE hop is plaintext.
3. **Image exchange networks.** Nuance PowerShare, Life Image, Intelerad/Ambra: managed DICOMweb gateways with a sales team.
4. **Actual DICOM TLS on 2762 or TLS-wrapped 11112.** Rare, and almost always inside a single health system rather than between organizations.

Whatever the envelope, the inner DIMSE is still gated by the same Called AE Title check from the previous section. The transport got authenticated. The DICOM verbs didn't. More commonly it's server-auth only, with the AE Title standing in as "client identity," which is not authentication.

When mutual TLS does show up, it usually rides a flat hospital-wide CA. Every modality's cert is trusted to act as every other. Revocation is never configured. The CA is a participation trophy.

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

With Nmap's default scripts enabled (`-sC`), the `dicom-ping` script runs automatically. `-A` will also pull it in, but `-A` is `-sC` plus OS detection, version detection, and traceroute, which could be more than you want to throw at a hospital network. For DICOM recon specifically, starting at the targeted `-sC -p 104` is best.

A typical run looks like this:

```
PORT     STATE SERVICE REASON
4242/tcp open  dicom   syn-ack
| dicom-ping:
|   dicom: DICOM Service Provider discovered!
|_  config: Called AET check enabled
```

A successful association (AE accepted) or even a rejected (A-ASSOCIATE-RJ) one is enough for Nmap to report. So the script sees the server speak DICOM and calls it a day.

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

The A-ASSOCIATE-AC packet has a User Information payload (Item Type `0x50`) containing nested Type-Length-Value (TLV) structures. The two fields the PR fingerprints:

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

Knowing the box is Orthanc 1.11.0 isn't enough. The next questions: what role does it play — archive, work-order server, scanner, print gateway — and which objects will it accept? Both answers sit in the A-ASSOCIATE-AC if you propose enough Presentation Contexts to draw them out. So I wrote [`dicom-enum`](https://github.com/tmart234/nmap_dicom/blob/main/scripts/dicom-enum.nse), a third NSE script that proposes about thirty contexts in one A-ASSOCIATE-RQ and buckets the responses.

Per [PS3.8 §9.3.3.2](https://dicom.nema.org/medical/dicom/current/output/html/part08.html), the AC returns one of five result codes per Presentation Context: accepted, user-rejection, abstract-syntax-not-supported, transfer-syntaxes-not-supported, no-reason. What lands in `accepted` is what the server will process on the next DIMSE op.

```
| dicom-enum:
|   association: accepted (max_pdu=16384, vendor=Orthanc 1.11.0)
|   service_classes:
|     QR-Patient-Root
|     QR-Study-Root
|     Storage
|     Verification
|   service_commands:
|     C-ECHO
|     C-FIND
|     C-STORE
|   modalities:
|     CT
|     MRI
|     PET
|     PET-CT
|     Ultrasound
|   inferred_device_class: Archive front-end
|   results:
|     accepted:
|       count: 15
|       items:
|         CT Image Storage - Explicit VR Little Endian
|         MR Image Storage - JPEG 2000 Image Compression (Lossless Only)
|         Encapsulated PDF Storage - Explicit VR Little Endian
```

Each accepted line pairs an object type with an encoding. DICOM defines a separate Storage class for every kind of object it carries — CT, MR, ultrasound, mammogram, encapsulated PDF, structured report, RT plan, presentation state, dozens more. A properly scoped SCP accepts only what it has reason to see, so a CT-facing endpoint that also accepts encapsulated PDFs is a misconfiguration worth flagging. The accepted list is also the ingestion boundary where a malformed or polyglot object becomes resident in the trusted archive — the bridge to [102]({% post_url 2026-04-16-dicom-file-format-security %}).

`service_commands` and `modalities` are the same accepted list sliced two ways. Commands are which DIMSE verbs are actually reachable here: your live attack surface, not the spec's. Modalities are what this box claims to handle, and a list that doesn't match the deployment story flags a misconfiguration.

`inferred_device_class` isn't spec-defined; it's practitioner shorthand for five real roles:

- **PACS/VNA.** The vault. Storage in, Q/R out, Storage Commitment and MPPS along for the ride. Whatever lands here was meant to stay forever.
- **Archive front-end.** Storage and Q/R, no workflow plumbing. A department PACS, a research archive, a Q/R cache fronting the real VNA — built to hold copies, not the original.
- **Modality.** The CT, the MR, the ultrasound. Accepts barely more than Verification and runs the oldest, least-patched code on the network.
- **RIS gateway.** Worklist only, refuses Storage. Demographics and schedules; the pixels live somewhere else.
- **Print server.** Hardcopy and film, a holdover from when radiologists read off light boxes — and one that has no business answering outside the modality VLAN.

These roles aren't standalone boxes; they're a pipeline. Modality → PACS/VNA → AI/ML inference → viewer re-parses the same object at each hop, under independent trust assumptions, and none of them re-authenticate the bytes that arrived. The SCP you fingerprint is just the first hop; whatever it accepts on `C-STORE` propagates downstream unchecked. That's why the capability map matters past recon — it's the surface that every later parser inherits.

`dicom-enum` is tagged `discovery` and `safe`, not `brute` and not `default`. Modalities are brittle, vendor support contracts get unhappy about unsolicited associations, and a default-category script proposing thirty contexts at every open port would land in the wrong inbox.

The recon flow, start to finish:

```bash
nmap -sC -p 104,11112,2762,4242 <target>           # ping + vendor/version
nmap --script dicom-brute <target>                  # if the AET gate rejects
nmap --script dicom-enum \
     --script-args dicom.called_aet=<AET> <target>  # capability map
```

## Beyond Nmap (Scapy)

Nmap tells you who you're talking to; [my Scapy DICOM contrib module](https://github.com/secdev/scapy/commit/ded1d73d7c779099964338803ad7b366c99d6820) is what you reach for next. Same A-ASSOCIATE on the wire, but you can craft anything: C-FIND, malformed image PDUs against a parser, or username/passcode brute force via the User Identity sub-item with the SecLists medical-devices wordlist. Workflow in a future post.

## Gaps for Future Work

- **No Spicy DICOM parser.** A Spicy grammar would compile to both Zeek and Suricata, so a hospital SOC could get DICOM-aware logging and inline detection from one parser. Nobody's written it.
- **No Metasploit modules.** No `auxiliary/scanner/dicom/*`, no exploits for the published CVEs in DCMTK or the major PACS stacks. Pentests reach for Python one-offs every time.
- **No DICOMweb NSE.** The HTTPS-fronted variant — WADO/QIDO/STOW, what every cloud imaging API actually speaks — has no Nmap coverage at all.
- **No public AET wordlist worth the name.** SecLists has a medical-devices file; it's a starting point, not a finished asset. Vendor-specific naming patterns (`MR_ER_3`, `PR-ct5_SCU`, `<MFG>_<MODALITY>_<ROOM>`) deserve their own corpus.

Somewhere right now a radiologist is opening a study that arrived over plaintext DIMSE, on a workstation whose AE Title is the brand name in all caps. The protocol is doing exactly what it was designed to do in 1993. Scapy next.

## References

1. Calderon, P. (2019). *New NSE library for DICOM and scripts `dicom-ping` and `dicom-brute`.* nmap-dev mailing list announcement: [seclists.org/nmap-dev/2019/q3/6](https://seclists.org/nmap-dev/2019/q3/6). Script docs: [`dicom-ping`](https://nmap.org/nsedoc/scripts/dicom-ping.html), [`dicom-brute`](https://nmap.org/nsedoc/scripts/dicom-brute.html).
2. Nmap PR adding DICOM vendor/version fingerprinting off the A-ASSOCIATE-AC (link TBD pending merge or reviewable state).
3. OFFIS DCMTK 3.6.9 release announcement (Dec 10, 2024): [forum.dcmtk.org/viewtopic.php?t=5429](https://forum.dcmtk.org/viewtopic.php?t=5429).
4. Shepard, S. J. (2004). *DICOM Basics for Radiographic and Fluoroscopic Systems.* 2004 AAPM Summer School: [aapm.org/meetings/04ss/documents/DICOMBasics.pdf](https://www.aapm.org/meetings/04ss/documents/DICOMBasics.pdf).
