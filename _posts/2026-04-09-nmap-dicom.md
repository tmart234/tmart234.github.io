---
layout: post
title: "DICOM Security 101: Network Security with Nmap"
mermaid: true
---

**Read the title.** Network protocol only. File stuff is in the [102]({% post_url 2026-04-16-dicom-file-format-security %}). If you get the urge to "you forgot about" me, please read that article.

Most people don't know that Nmap (the port scanning tool everyone and their grandma has used) supports DICOM. And not in a half-baked way: there are Nmap scripts revealing network protocol-level insights. So this post attempts to give you some basic protocol fluency, review overall network attack surface with existing Nmap DICOM support, cover my Nmap DICOM PR on fingerprinting DICOM systems, and touch briefly on my Scapy DICOM PR.

## Prior Work

The baseline DICOM tooling in Nmap is Paulino Calderon's work [[1]](#references): he wrote the `dicom` NSE (Nmap Scripting engine) library, the `dicom-ping` discovery script, and the `dicom-brute` AE Title brute-forcer script in 2019. The DICOM fingerprinting, discussed later, is about tying up lose ends from the original ping script. 

## Flavors of DICOM

Before the Nmap tour, let's talk about different flavors of networked DICOM.

### Ports

| Service | Port(s) |
| --- | --- |
| DICOM (upper-layer protocol) | 104, 11112 |
| DICOM over TLS | 2762 |
| DICOMweb | 80, 443 |

DICOMweb (WADO/QIDO/STOW) rides HTTPS, so on paper auth is in a better place: bearer tokens, OAuth, standard TLS, all the REST-API hygiene the upper-layer protocol never had. In practice, deployments ship with no auth or vendor default credentials, and the attack surface collapses into "under-configured REST API with PHI behind it." No Nmap NSE scripts exist for DICOMweb yet; it's out of scope for this post, but flagged as open tooling work.

### DIMSE Services

After association, DIMSE splits into two families. **C-services** (Composite) act on clinical objects themselves: store, find, get, move. This is the data plane, where PHI lives and where nearly all pentest and threat-model attention goes. **N-services** (Normalized) act on workflow state: MPPS updates, storage-commitment results, print jobs.

N-services get far less scrutiny. Once a peer is associated there's no per-verb auth, so an `N-SET` that flips an MPPS to COMPLETED or a forged storage-commitment `N-EVENT-REPORT` lands with the same trust as a `C-STORE`. No pixels touched, no hash mismatch, just corrupted workflow. The ones you need to know:

| Service | Why a pentester cares |
| --- | --- |
| `C-ECHO` | Protocol ping. Sent over an established A-ASSOCIATE, the step Nmap's `dicom-ping` skips. |
| `C-STORE` | Upload DICOM objects to the peer. Entry point for file-format fuzzing. |
| `C-FIND` | Query: patient lists, studies, series, Modality Worklist. PHI exposure or authorization-scoping check. |
| `C-MOVE` | Client names a destination AE Title; server opens a new A-ASSOCIATE there and C-STOREs the objects to it. SSRF-adjacent pivot primitive. |
| `C-GET` | Server returns objects over the current association — no second outbound connection, so not a pivot. Rare because it needs reverse-role negotiation for Storage SOP classes; try when `C-MOVE` is blocked. |
| **N-services** (`N-CREATE`, `N-SET`, `N-ACTION`, `N-EVENT-REPORT`, `N-GET`) | Workflow/event verbs: MPPS state, Storage Commitment receipts, Print. No pixel data, so audit rules and threat models routinely skip them. |

Those three layers — AE Titles gate *whether you can ask*, presentation contexts gate *what you can ask*, DIMSE services are *what you ask for* — are what the next section frames as gates. Real deployments get the layering wrong constantly.

## Auth in DICOM

A-ASSOCIATE layers three authorization controls, none of which prove identity (that's authentication, below). The server is deciding: can this peer connect, what operations is the association allowed to perform, and in what encodings.

| Control | What it authorizes | Granularity | Typical failure |
| --- | --- | --- | --- |
| Called AE Title (fixed header) | Whether the association is accepted at all | Per-peer | `ANY-SCP` wildcard accepts any caller |
| Abstract Syntax / SOP Class UID (item 0x20 proposed → 0x21 accepted) | Which operation classes (Storage, Q/R, MWL, MPPS, Print) | Per-operation-class | Storage accepted when the role only needs Query |
| Transfer Syntax (sub-item 0x40 inside 0x21) | Which byte encodings the accepted operations may use | Per-encoding | Obsolete/rare syntaxes accepted (Implicit VR downgrade, rare JPEG variants) |

Authentication is a separate conversation from the gates above. For network authentication, DICOM supports two mechanisms:

- **DICOM TLS** — authenticates the transport peer. Mutual-auth capable.
- **User Identity Negotiation** — authenticates the user. [DICOM PS3.7 §D.3.3.7](https://dicom.nema.org/medical/dicom/current/output/html/part07.html) defines a User Identity sub-item (Type `0x58`) that rides inside the A-ASSOCIATE-RQ and supports one of:
    - username only
    - username + passcode
    - Kerberos service ticket
    - SAML assertion
    - JSON Web Token (JWT)

The catch: **there is no dedicated reject *reason* code for a credential miss**. Per [PS3.7 §D.3.3.7.3](https://dicom.nema.org/medical/dicom/current/output/chtml/part07/sect_D.3.3.7.3.html), a spec-compliant acceptor rejects user identity as rejected-permanent with Source = `2` (service-provider, ACSE) and Reason = `1` (no-reason-given) — i.e. `1/2/1` — which *is* distinguishable from an AE Title miss at `1/1/7` or `1/1/1` (Source = `1`, service-user). Some implementations flatten both to `1/1/1` anyway, and in that flattened case the only remaining tell is whether you sent a `0x58` sub-item in your RQ. Check the Source byte first; fall back to the `0x58`-presence heuristic when it's useless.

### TLS: Specified, Inconsistently Deployed

[PS3.15](https://dicom.nema.org/medical/dicom/current/output/html/part15.html) defines TLS profiles (including BCP 195-aligned ones) with mutual authentication. The spec is fine. The *deployments* are not.

There's no STARTTLS-style upgrade in A-ASSOCIATE and no in-band signal that a peer requires TLS. A listener on 104 either speaks DICOM in the clear or it speaks TLS, and you find out by probing.

Port 2762 is `dicom-tls` per IANA, but plenty of real deployments just run TLS on 104 or 11112 because the vendor's config has exactly one "DICOM port" field and a "use TLS" checkbox. The port tells you very little on its own.

Mutual TLS is rare in the field. When it exists, it's frequently server-auth only with the AE Title standing in as the "client identity", which, per the previous section, is not authentication.

The other common pattern is mutual TLS against a flat, hospital-wide CA, which makes every modality's cert trusted to act as every other modality. Revocation checking? Almost never configured.

And this is the piece most people miss: **the layering**. TLS authenticates the transport peer. AE Title still gates the DICOM payload. "We have mutual TLS" does not mean "only authorized clients can C-STORE."

## What Nmap Already Does for DICOM

With the auth model in hand, here's what Nmap already ships to probe it. Two DICOM-aware NSE scripts, `dicom-ping` and `dicom-brute` [[1]](#references), plus the generic TCP port scanning you'd get on any service. I'll walk through them in order of increasing usefulness, then get to the vendor/version fingerprinting my unmerged PR adds.

### 1. Port Scanning

```
nmap -sS -p 104 <target>
```

Without any NSE scripts, you can tell if DICOM-related ports are open. Port 104 is the standard DICOM port. But let's be honest, knowing a port is open tells you almost nothing. It's like confirming a building has a door. Congratulations.

### 2. DICOM Discovery (dicom-ping)

```
nmap -sC -p 104 <target>
```

With Nmap's default scripts enabled (`-sC`), the `dicom-ping` script runs automatically. `-A` will also pull it in, but `-A` is `-sC` plus OS detection, version detection, and traceroute, which could be more than you want to throw at a hospital network. For DICOM recon specifically, starting at the targeted `-sC -p 104` is best. Either way, here's the thing: this "ping" is not a real DICOM ping because it never sends a C-ECHO. It only does the first half, the A-ASSOCIATE request/response handshake. That's it.

A successful association (AE accepted) or even an unsuccessful (AE-reject response) is enough for Nmap to report: `DICOM Service Provider discovered!` So the script sees the server speak DICOM and calls it a day. No full C-ECHO, no verification of actual DICOM service capability. Just the associate handshake.

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

One script-specific note: when `dicom-ping` gets an association accepted using the generic `ANY-SCP` called AE Title, it reports `Any AET is accepted (Insecure)` — the server is treating the wildcard identifier as a valid peer, so the Called AE Title check isn't filtering anything.

### 3. AE Title Brute Force

```
nmap --script dicom-brute <target>
# With a custom wordlist:
nmap --script dicom-brute --script-args passdb=aets.txt <target>
```

`dicom-brute` is categorized under `auth` and `brute`, not `default`, so `-sC` won't pull it in. You have to call it explicitly. The most important script argument here is `passdb`, which lets you specify a wordlist for guessing the called AE Title.

If `dicom-ping` came back rejected, or came back accepted under `ANY-SCP` and you want to enumerate real AETs, this is your next move. Feed it a list of common AE Titles and see what sticks.

#### What the Reject Tells You

When the server sends A-ASSOCIATE-RJ instead of AC, [PS3.8 §9.3.4](https://dicom.nema.org/medical/dicom/current/output/html/part08.html) defines the `(Result, Source, Reason)` triple in the reject PDU. Decode it:

| Result / Source / Reason | What likely happened | Pentester move |
| --- | --- | --- |
| 1 / 1 / 1 (rejected permanent, service-user, no reason given) | AE Title miss. On stacks that flatten credential rejections into this code (rather than the spec-compliant `1/2/1`), it can also mean a credential miss — **without** a `0x58` sub-item in your RQ, assume AE Title; **with** a `0x58`, could be either. | Try an AE Title wordlist first; once you've pinned a valid AET, re-run *with* a `0x58` and pivot to a credential wordlist. |
| 1 / 1 / 7 (called AET not recognized) | AE Title gate, explicit | Brute AE Title |
| 1 / 2 / 1 (rejected permanent, service-provider/ACSE, no reason given) | Spec-compliant credential miss per [PS3.7 §D.3.3.7.3](https://dicom.nema.org/medical/dicom/current/output/chtml/part07/sect_D.3.3.7.3.html). AE Title was accepted, user identity was not. | Keep the AET, brute `0x58` credential forms. |

Order of operations: on spec-compliant stacks the Source byte alone separates the two gates (`1/1/*` = AE Title, `1/2/*` = user identity), so you can run the campaigns independently. On stacks that flatten everything to `1/1/1`, the code means different things depending on whether your RQ carried a `0x58`, so brute the AE Title gate *first* (no `0x58`), then, once the AET is good, add `0x58` and brute credentials. (`1/1/2 protocol version not supported` also exists, rare in practice; flip the Protocol-Version bits and re-propose if you hit it.)

The AC tells you who built the stack, the RJ tells you which gate you tripped on.

## Adding Vendor & Version Fingerprinting

I submitted a PR to Nmap to add basic DICOM vendor and version detection [[2]](#references). Seems boring on the surface, but it's core to what Nmap does: fingerprinting. And I felt strongly that default tooling should have default support for identifying what DICOM implementation you're talking to.

Who knows when the PR gets merged, so I'm writing about it now. Plus, I have fancy diagrams — and by "fancy" I mean one JPEG and some ASCII art.

### The Insight

After looking at the DICOM A-ASSOCIATE packets that Nmap's `dicom-ping` script already exchanges, I noticed something useful: the A-ASSOCIATE-AC (accept) response contains reliable vendor and version information just sitting there. No extra packets.

{% include associate_ac_pdu.html %}

Each Item Type `0x21` is the server's commitment to one **Presentation Context** from the RQ's proposals: a Presentation Context ID paired with exactly one Accepted Transfer Syntax (sub-item `0x40`) for a given Abstract Syntax (SOP Class UID: Verification, Storage, Query/Retrieve, Modality Worklist). The accepted IDs gate every DIMSE op that follows: propose Storage and get it accepted, you can C-STORE; don't propose it, or get it rejected, and you can't. That negotiation is itself an attack primitive: downgrade to Implicit VR to strip type information, force uncompressed to dodge codec paths, or pick a rare JPEG variant to steer the peer onto its dustiest decoder.

The A-ASSOCIATE-AC packet also has a User Information payload (Item Type `0x50`) containing nested Type-Length-Value (TLV) structures. A few are important:

**Implementation Class UID (Type 0x52):** A DICOM UID in dot-notation, OID-shaped, with a root arc typically registered in an OID registry. The DICOM spec is explicit that UIDs "shall not be parsed" for semantic meaning beyond uniqueness, but in practice the root arc reliably identifies the implementer, which is exactly what we want for fingerprinting. For example, [`1.2.276.0.7230010.3`](https://oid-base.com/get/1.2.276.0.7230010.3) maps to OFFIS DCMTK (a software library), while [`1.2.840.113619`](https://oid-base.com/get/1.2.840.113619) maps to GE Medical Systems (a device manufacturer) — exactly the sw-lib-vs-OEM distinction the next section turns into a fingerprinting primitive.

**Implementation Version Name (Type 0x55):** A free-form string parsed for version information. For example, `OFFIS_DCMTK_369` parses to DCMTK version 3.6.9 [[3]](#references). Worth noting: per the spec, 0x52 is mandatory in the A-ASSOCIATE-AC but 0x55 is *optional*, so a conforming implementation can omit it entirely. Most real-world implementations do send it, and the PR falls back gracefully when they don't.

#### Why You Need to Look Up Both

I spent time here investigating which of these actually matters, and the answer is: both, but for different reasons.

In theory `0x52`, the Implementation Class UID, is the authoritative vendor identifier for who (MDM) manufactured the device. As the name *Implementation* implies... it identifies the vendor implementing the DICOM thing. But in practice, a lot of lazy MDMs ship devices with a third-party software stack's UID (DCMTK, dcm4che, pynetdicom) and don't override it. So `0x52` would happily report "OFFIS" on a device that's actually a Brand X modality with DCMTK linked in. You can't trust either field in isolation.

From a pentester's point of view, `0x55` is probably the most important. The Version Name tends to track the software that's actually on the wire, parsing PDUs. That's the majority of the attack surface: which library's bugs you get, regardless of whose product.

The PR handles this by doing table lookups on **both** fields independently and surfacing what each one says. So:

- If `0x52` and `0x55` disagree, that's a useful signal: an OEM customized the stack, and you should look up the OID to find who.
- If both fields point at the same open-source stack, the manufacturer probably never registered their own OID.

### Beyond Nmap (Scapy)

The A-ASSOCIATE-RQ sent by the client carries the same `0x50` User Information structure, optionally including the User Identity sub-item covered earlier. Even after a successful association, some implementations scope DIMSE-level authorization by AE Title or User Identity credentials, so "associated" doesn't always mean "full access."

This is where my [Scapy DICOM contrib module](https://github.com/secdev/scapy/commit/ded1d73d7c779099964338803ad7b366c99d6820) comes in. Once Nmap tells you who or what you're talking to, you can use Scapy to send a C-FIND, or craft a malformed image PDU to test a parser. I'll cover that workflow in a future post.

As a taste, here's what the Scapy packet format looks like when crafting an A-ASSOCIATE-RQ that carries username and passcode:

```python
DICOM()/A_ASSOCIATE_RQ(calling_ae_title="PENTEST", called_ae_title="ANY-SCP",
    variable_items=[DICOMUserIdentity(user_identity_type=2,
        primary_field=b"admin", secondary_field=b"password")])
```
Similar to the AE title brute force, we can hook username and password variables to cycle through any standard or custom wordlists (ex seclists medical devices). 

## References

1. Calderon, P. (2019). *New NSE library for DICOM and scripts `dicom-ping` and `dicom-brute`.* nmap-dev mailing list announcement: [seclists.org/nmap-dev/2019/q3/6](https://seclists.org/nmap-dev/2019/q3/6). Script docs: [`dicom-ping`](https://nmap.org/nsedoc/scripts/dicom-ping.html), [`dicom-brute`](https://nmap.org/nsedoc/scripts/dicom-brute.html).
2. Nmap PR adding DICOM vendor/version fingerprinting off the A-ASSOCIATE-AC (link TBD pending merge or reviewable state).
3. OFFIS DCMTK 3.6.9 release announcement (Dec 10, 2024): [forum.dcmtk.org/viewtopic.php?t=5429](https://forum.dcmtk.org/viewtopic.php?t=5429).
