---
layout: post
title: "DICOM Security 101: Understanding Network Protocol Security with Nmap"
---

Most people don't know that Nmap, the port scanning tool everyone and their grandma has used, actually supports DICOM. And not in some half-baked way — there are real NSE scripts doing real protocol-level work. As someone who works on medical devices, I felt the need to break down a few DICOM security concepts so you can better understand how to use the supported tooling.

## The Protocol at a Glance

Before the Nmap tour, a minimum viable mental model. If you already live in this protocol you can skip ahead, but a lot of what follows only makes sense once you know what's being negotiated on the wire.

### Ports

| Service | Port(s) |
| --- | --- |
| DICOM (upper-layer protocol) | 104, 11112 |
| DICOM over TLS | 2762 |
| DICOMweb | 80, 443 |

DICOMweb is the HTTP/REST sibling — WADO-RS, QIDO-RS, STOW-RS over plain HTTP(S). It's mostly out of scope for this post, but it's a rich target and there's real room for future NSE scripts pointed at it. Keeping this simple on purpose.

### Presentation Contexts: SOP Classes and Transfer Syntaxes

A-ASSOCIATE isn't just "here's my AE Title (AET), here are my credentials, let me in." It's a negotiation. The client proposes a list of **Presentation Contexts**, each one a pair of:

- an **Abstract Syntax** — a SOP Class UID identifying *what* you want to do: Verification (C-ECHO), Storage, Query/Retrieve, Modality Worklist, and so on.
- one or more **Transfer Syntaxes** — *how* the bytes are encoded on the wire: Implicit VR Little Endian, Explicit VR Little Endian, the JPEG family, RLE, and friends.

The server accepts or rejects each one and hands back a Presentation Context ID. Those IDs are the gate — they decide which DIMSE operations the client can even ask for during the rest of the session. Propose Storage, get Storage accepted, now you can C-STORE. Don't propose it, or get it rejected, and you can't.

From a security standpoint this is a big deal, and it's the part most "DICOM security" posts skip. Transfer syntax negotiation in particular is a documented fuzzing surface: downgrade to Implicit VR to strip type information, force uncompressed to dodge codec code paths, or pick a rarely-exercised JPEG variant to steer the peer onto the dusty, under-tested decoder. The negotiation itself is an attack primitive.

### DIMSE Services

DIMSE is the verb layer that rides on top of an accepted association. The ones you need to know:

- `C-ECHO` — protocol ping. Are you alive and do you speak DICOM.
- `C-STORE` — write a DICOM object to the peer. This is the "upload arbitrary DICOM to the PACS" surface. Everything about file-format fuzzing aims here.
- `C-FIND` — query metadata. Patient lists, studies, series, Modality Worklist entries.
- `C-MOVE` — tell the peer to send data to a third AE over a new association. Classic SSRF-adjacent — *you* pick the destination.
- `C-GET` — pull data back on the existing association. Less common in the wild, mostly because `C-MOVE` exists.
- Plus the **N-services** (`N-CREATE`, `N-SET`, `N-ACTION`, `N-EVENT-REPORT`, `N-GET`) used by Modality Performed Procedure Step, Storage Commitment, Print, and other workflow/event-reporting SOP Classes.

The mental model that makes the rest of the post click: **presentation contexts gate *what you can ask*, DIMSE services are *what you ask for*, and AE Titles gate *whether you're allowed to ask at all*.** Those are three different checks and real deployments get the layering wrong constantly.

## What Nmap Already Does for DICOM

Nmap ships two DICOM-aware NSE scripts — `dicom-ping` and `dicom-brute` — plus the generic TCP port scanning you'd get on any service. I'll walk through them in order of increasing usefulness, then get to the vendor/version fingerprinting my unmerged PR adds.

### 1. Port Scanning

```
nmap -sS -p 104 <target>
```

Without any NSE scripts, you can tell if DICOM-related ports are open. Port 104 is the standard DICOM port. But let's be honest, knowing a port is open tells you almost nothing. It's like confirming a building has a door. Congratulations.

### 2. DICOM Discovery (dicom-ping)

```
nmap -sC -p 104 <target>
```

Now we're getting somewhere. With Nmap's default scripts enabled (`-sC`), the `dicom-ping` script runs automatically. `-A` will also pull it in, but `-A` is `-sC` plus OS detection, version detection, and traceroute — more than you probably want to throw at a hospital network. For DICOM recon specifically, the targeted `-sC -p 104` form is the right invocation. Either way, here's the thing most people don't realize: this "ping" is not a real DICOM ping. It never sends a C-ECHO. It only does the first half — the A-ASSOCIATE request/response handshake.

A successful association or even an AE-reject response is enough for Nmap to report: **"DICOM Service Provider discovered!"** That's it. The script sees the server speak DICOM and calls it a day. No C-ECHO, no verification of actual DICOM service capability. Just the handshake.

#### How This Works

Since everything Nmap does for DICOM — discovery, "insecure AE Title" detection, brute force, and the vendor/version fingerprinting I'll get to below — rides on this same A-ASSOCIATE exchange, it's worth pausing on the actual wire flow before going further.

![Nmap DICOM ping sequence]({{ site.baseurl }}/public/associate.jpg)

Nmap sends an A-ASSOCIATE-RQ, the server responds with an A-ASSOCIATE-AC (accept) or A-ASSOCIATE-RJ (reject), and Nmap drops the connection. The C-ECHO phase that would make this a "real" DICOM ping is skipped entirely. Every Nmap DICOM feature is built on parsing whatever comes back in that single response — no extra packets, no extra noise on the network. Keep this mental model in mind for the rest of the article.

### 3. AE Title "Authentication" (It's Not)

(Still the same `dicom-ping` script — this is just a different finding it can surface, not a separate capability.) If Nmap's `dicom-ping` gets an association accepted with the generic "ANY-SCP" AE Title, you'll see: **"Any AET is accepted (Insecure)"**.

Now let me be very clear about what AE Titles actually are. They're identifiers. That's it. Somewhere along the way, many DICOM systems repurposed them as a weak access-control mechanism. At best, they're ACL-ish. They are absolutely **NOT** real cryptographic authentication. Having "Any AE Title accepted" is basically a wildcard (`*`) in your ACL — a lightweight authorization control, not a cryptographic one. The door is wide open.

#### What DICOM Actually Offers for Authentication

That said, there are some edge cases. [DICOM PS3.7 §D.3.3.7](https://dicom.nema.org/medical/dicom/current/output/html/part07.html) defines the User Identity Negotiation sub-item itself, and [PS3.15](https://dicom.nema.org/medical/dicom/current/output/html/part15.html) defines the security profiles that put these mechanisms to use. Together they cover:

- **TLS-based Secure Transport Connection Profiles** (PS3.15) — certificate-based mutual authentication at the transport layer.
- **User Identity Negotiation** (PS3.7, via the A-ASSOCIATE User Identity sub-item, referenced by PS3.15 profiles like the Basic User Identity Association Profile and Kerberos Identity Negotiation Association Profile) — username only, username + passcode, Kerberos service ticket, SAML assertion, and JWT.

So theoretically, even with an accepted AE Title, the server *might* also require User Identity credentials — but this is checked during the same A-ASSOCIATE handshake, not after it. In practice? Don't count on it — and even when you do, the username/passcode path is a fat target. Because the rejection reason codes differ between an AE Title miss and a credential miss, you can usually brute force them individually — nail the AE Title first, then pivot to credentials if User Identity is in play.

### TLS: Specified, Rarely Deployed, Often Broken

PS3.15 defines TLS profiles — including BCP 195-aligned ones — with mutual authentication. The spec is fine. The *deployments* are not.

There's no STARTTLS-style upgrade in A-ASSOCIATE and no in-band signal that a peer requires TLS. A listener on 104 either speaks DICOM in the clear or it speaks TLS, and you find out by probing. Port 2762 is `dicom-tls` per IANA, but plenty of real deployments just run TLS on 104 or 11112 because the vendor's config has exactly one "DICOM port" field and a "use TLS" checkbox. The port tells you very little on its own.

Mutual TLS is rare in the field. When it exists, it's frequently server-auth only with the AE Title standing in as the "client identity" — which, per the previous section, is not authentication. The other common pattern is mutual TLS against a flat, hospital-wide CA, which makes every modality's cert trusted to act as every other modality. Revocation checking? Almost never configured.

And this is the piece most people miss: **the layering**. TLS authenticates the transport peer. AE Title still gates the DICOM payload. "We have mutual TLS" does not mean "only authorized clients can C-STORE" — it means "only clients with a trusted cert can connect, and then AE Title ACLs decide what they can do." If the ACL is `ANY-SCP`, congratulations — you've got a cryptographically authenticated wildcard.

### 4. AE Title Brute Force

```
nmap --script dicom-brute <target>
# With a custom wordlist:
nmap --script dicom-brute --script-args passdb=aets.txt <target>
```

`dicom-brute` is categorized under `auth` and `brute` — not `default` — so `-sC` won't pull it in. You have to call it explicitly. The most important script argument here is `passdb`, which lets you specify a wordlist for guessing the called AE Title.

If the generic AE Title got rejected in step 2, this is your next move. Feed it a list of common AE Titles and see what sticks.

## Adding Vendor & Version Fingerprinting

I submitted a PR to Nmap to add basic DICOM vendor and version detection. Seems boring on the surface, but it's core to what Nmap does — fingerprinting. And I felt strongly that default tooling should have default support for identifying what DICOM implementation you're talking to.

Who knows when the PR gets merged, so I'm writing about it now. Plus, I have fancy diagrams.

### The Insight

After looking at the DICOM A-ASSOCIATE packets that Nmap's `dicom-ping` script already exchanges, I noticed something useful: the A-ASSOCIATE-AC (accept) response contains reliable vendor and version information just sitting there. No extra packets.

{% include associate_ac_pdu.html %}

The A-ASSOCIATE-AC packet has a User Information payload (Item Type `0x50`) containing nested Type-Length-Value (TLV) structures. A few are important:

**Implementation Class UID (Type 0x52):** A DICOM UID — dot-notation, OID-shaped, with a root arc typically registered in an OID registry. The DICOM spec is explicit that UIDs "shall not be parsed" for semantic meaning beyond uniqueness, but in practice the root arc reliably identifies the implementer, which is exactly what we want for fingerprinting. The tension is real; owning it is the insight. For example, [`1.2.276.0.7230010.3`](https://oid-base.com/get/1.2.276.0.7230010.3) maps to OFFIS DCMTK. On paper this is the "who built this" device field — as the name *Implementation* implies, it's supposed to identify the vendor implementing the DICOM thing.

**Implementation Version Name (Type 0x55):** A free-form string parsed for version information. For example, `OFFIS_DCMTK_369` parses to DCMTK version 3.6.9. Worth noting: per the spec, 0x52 is mandatory in the A-ASSOCIATE-AC but 0x55 is *optional* — a conforming implementation can omit it entirely. Most real-world implementations do send it, and the PR falls back gracefully when they don't.

#### Why You Need to Look Up Both

I spent time investigating which of these actually matters, and the answer is: both, for different reasons.

In theory `0x52` is the authoritative vendor identifier for who manufactured the device. In practice, lazy vendors ship devices with a third-party stack (DCMTK, dcm4che, pynetdicom) and never override the Implementation Class UID or Version Name. So `0x52` happily reports "OFFIS" on a device that's actually a Brand X modality with DCMTK linked in. You can't trust either field in isolation.

The PR handles this by doing table lookups on **both** fields independently and surfacing what each one says:

- If `0x52` and `0x55` disagree, that's a useful signal — an OEM customized the stack, and you should look up the OID to find who.
- If both fields point at the same open-source stack, the manufacturer probably never registered their own OID.

From a pentester's point of view, `0x55` is probably the most important. Implementation *Class* is about the OEM vendor's identity on paper, but the Version Name tends to track the code that's actually on the wire parsing your PDUs. That's the attack surface — the version string tells you which library's bugs you get to play with, regardless of whose DICOM product you're testing.

### Beyond Nmap

The A-ASSOCIATE-RQ sent by the client carries the same `0x50` User Information structure — including an optional User Identity sub-item (Type `0x58`) that supports username/passcode, Kerberos, SAML, and JWT. Even after a successful association, some implementations scope DIMSE-level authorization by AE Title or User Identity credentials — so "associated" doesn't always mean "full access."

This is where my Scapy DICOM contrib module comes in — once Nmap tells you you're talking to DCMTK 3.6.9, you can use Scapy to send a C-FIND and see if the AE Title you negotiated actually has query access, or craft a malformed PDU to test the parser. I'll cover that workflow in a future post.

## Why This Matters

Most hospital network assessments treat DICOM as a black box on port 104. The tooling to look inside that box already ships with Nmap — most people just don't know it's there. Vendor fingerprinting closes the loop: you go from "something speaks DICOM" to "this specific library version is parsing my PDUs," which is the difference between a finding and an actionable finding.

And there's a lot more room here. Almost all of this — port discovery, auth probing, vendor fingerprinting — has a direct DICOMweb analog against WADO/QIDO/STOW endpoints, and as far as I can tell nobody has written the NSE scripts for it yet. Plenty of future work.
