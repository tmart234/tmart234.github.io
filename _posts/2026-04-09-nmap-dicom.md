---
layout: post
title: "NMAP's Hidden DICOM Support"
---

Most people don't know that NMAP, the port scanning tool everyone and their mother has used, actually supports DICOM. And not in some half-baked "we added a port number" way. There are real NSE scripts doing real DICOM protocol work. As someone who works on medical devices, I felt the need to break this down because the default tooling should have been doing more here all along.

## What NMAP Already Does for DICOM

There are essentially four levels of DICOM support in NMAP, each getting progressively more interesting.

### 1. Port Scanning

```
nmap -sS -p 104 <target>
```

Without any NSE scripts, you can tell if DICOM-related ports are open. Port 104 is the standard DICOM port. But let's be honest, knowing a port is open tells you almost nothing. It's like confirming a building has a door. Congratulations.

### 2. DICOM Discovery (dicom-ping)

```
nmap -sC <target>
# or
nmap -A <target>
```

Now we're getting somewhere. With NMAP's default scripts enabled (`-sC` or `-A`), the `dicom-ping` script runs automatically. But here's the thing most people don't realize: this "ping" is not a real DICOM ping. It never sends a C-ECHO. It only does the first half — the A-ASSOCIATE request/response handshake.

![DICOM A-ASSOCIATE negotiation]({{ site.baseurl }}/public/spec_associate.PNG)

A successful association or even an AE-reject response is enough for NMAP to report: **"DICOM Service Provider discovered!"** That's it. The script sees the server speak DICOM and calls it a day. No C-ECHO, no verification of actual DICOM service capability. Just the handshake.

#### How This Works in Practice

Since everything NMAP does for DICOM — discovery, "insecure AET" detection, brute force, and the vendor/version fingerprinting I'll get to below — rides on this same A-ASSOCIATE exchange, it's worth pausing on the actual wire flow before going further.

![Nmap DICOM ping sequence]({{ site.baseurl }}/public/associate.jpg)

NMAP sends an A-ASSOCIATE-RQ, the server responds with an A-ASSOCIATE-AC (accept) or A-ASSOCIATE-RJ (reject), and NMAP drops the connection. The C-ECHO phase that would make this a "real" DICOM ping is skipped entirely. Every NMAP DICOM feature is built on parsing whatever comes back in that single response — no extra packets, no extra noise on the network. Keep this mental model in mind for the rest of the article.

### 3. "Any AET is Accepted (Insecure)"

This is where it gets spicy. If NMAP's dicom-ping gets an association accepted with the generic "ANY-SCP" AE Title, you'll see: **"Any AET is accepted (Insecure)"**.

Now let me be very clear about what AE Titles actually are. They're identifiers. That's it. Somewhere along the way, many DICOM systems repurposed them as a weak access-control mechanism. At best, they're ACL-ish. They are absolutely **NOT** real cryptographic authentication. Having "Any AE Title accepted" is basically a wildcard (`*`) in your ACL. The door is wide open.

That said, there are some edge cases. [DICOM PS3.15](https://dicom.nema.org/medical/dicom/current/output/html/part15.html) defines actual authentication mechanisms that *can* be negotiated on top of the association. Specifically, it covers:

- **TLS-based Secure Transport Connection Profiles** — certificate-based mutual authentication over TLS (BCP 195 profiles).
- **User Identity Negotiation** (via the A-ASSOCIATE User Identity sub-item) — username only, username + passcode, Kerberos service ticket, SAML assertion, and JWT.
- **ISCL** (Integrated Secure Communication Layer) — legacy symmetric-key profile, still referenced but rarely seen in the wild.

So theoretically, even with an accepted AE title, you *might* encounter real authentication further down the line. In practice? Don't count on it — and even when you do, the username/passcode path is a fat target. NMAP doesn't currently go after User Identity Negotiation, but the A-ASSOCIATE User Identity sub-item is very much brute-forceable with [DICOM Scapy](#) (TBD article — I'll drop a link here once it's up). That's a gap worth keeping in mind: `dicom-brute` only chews on AE Titles, not on the actual authentication sub-item PS3.15 defines.

### 4. AE Title Brute Force

```
nmap --script dicom-brute <target>
# With a custom wordlist:
nmap --script dicom-brute --script-args passdb=aets.txt <target>
```

Since brute forcing is deemed "aggressive" by the NMAP project, `dicom-brute` doesn't run with the default scripts option. You have to explicitly call it. The most important script argument here is `passdb`, which lets you specify a wordlist for guessing the called AE Title.

If the generic AE Title got rejected in step 2, this is your next move. Feed it a list of common AE Titles and see what sticks.

## Adding Vendor & Version Fingerprinting

I submitted a PR to NMAP to add basic DICOM vendor and version detection. Seems boring on the surface, but it's core to what NMAP does — fingerprinting. And I felt strongly that default tooling should have default support for identifying what DICOM implementation you're talking to.

Who knows when the PR gets merged, so I'm writing about it now. Plus, I have fancy diagrams.

### The Insight

After looking at the DICOM A-ASSOCIATE packets that NMAP's dicom-ping script already exchanges, I noticed something useful: the A-ASSOCIATE-AC (accept) response contains reliable vendor and version information just sitting there in the packet. No extra network traffic needed.

![A-ASSOCIATE-AC PDU structure]({{ site.baseurl }}/public/associate_pdu.jpg)

The A-ASSOCIATE-AC packet has a User Information payload (Item Type `0x50`) containing nested TLV (Type-Length-Value) structures. Two of them are gold:

**Implementation Class UID (Type 0x52):** An OID (Object Identifier) whose root can be looked up in an OID registry. For example, `1.2.276.0.7230010` maps to OFFIS, the organization behind DCMTK. On paper this is the "who built this" field — as the name *Implementation* implies, it's supposed to identify the vendor implementing the DICOM stack.

**Implementation Version Name (Type 0x55):** A free-form string parsed for version information. For example, `OFFIS_DCMTK_369` parses to DCMTK version 3.6.9.

#### Why You Need to Look Up Both

We had a lot of back-and-forth on the PR about which of these two actually matters, and the answer is: both, for different reasons.

In theory `0x52` is the authoritative vendor identifier. In practice, lazy vendors ship devices with a third-party stack (DCMTK, dcm4che, pynetdicom) and never override the Implementation Class UID or Version Name. So `0x52` happily reports "OFFIS" on a device that's actually a Brand X modality with DCMTK linked in. You can't trust either field in isolation.

The PR handles this by doing registry lookups on **both** fields independently and surfacing what each one says:

- If `0x52` and `0x55` agree on the underlying stack, you've got a confident fingerprint.
- If they disagree, that's itself a useful signal — someone customized one but not the other.
- If both point at a well-known open-source stack on a commercial device, you've just caught a lazy OEM integration.

From a pentester's point of view, `0x55` is the one I reach for first. Implementation *Class* is about the vendor's identity on paper, but the Version Name tends to track the code that's actually on the wire parsing your PDUs. That's the attack surface — the version string tells you which library's bugs you get to play with, regardless of whose logo is on the chassis.

### AE Titles Are Not Authentication

I keep coming back to this because it bears repeating. DICOM AE Titles are **not** authentication. They're closer to an ACL. "Any AE Title accepted" is the equivalent of a wildcard in your access control list. It means anyone who speaks DICOM can walk in.

Could there be actual authentication required for specific DICOM actions even after association? Yes — PS3.15's TLS and User Identity Negotiation profiles above — but the reality on most systems I've encountered is that once you're past the AE Title, you're in.

This is where my Scapy DICOM work comes in handy — for scripting out the next steps of an assessment beyond what NMAP provides. Once you've fingerprinted the vendor and version with NMAP, you know exactly what you're dealing with and can tailor your approach accordingly.

## Why This Matters

NMAP's DICOM support is more capable than most security folks realize, and adding vendor/version fingerprinting fills a real gap. When you're doing recon on a hospital network or testing a medical device, knowing that port 104 is open is table stakes. Knowing it's running DCMTK 3.6.9? That's actionable intelligence.
