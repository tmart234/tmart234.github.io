---
layout: post
title: "DICOM Security 102: Diving into Files"
last_modified_at: 2026-04-16
---

The [101]({% post_url 2026-04-09-nmap-dicom %}) covered what happens on the wire: A-ASSOCIATE handshakes, AE Title "authentication," vendor fingerprinting. This one covers what's inside the files. DICOM's Part 10 file format was designed for interoperability and absolutely nothing else. No integrity by default. No authentication. No validation. That makes it a file format worth understanding if you're testing or defending imaging systems.

## 128 Bytes of Free Parking

Every DICOM Part 10 file starts with a 128-byte preamble, followed by the four-byte magic string `DICM`. The spec is explicit about what goes in that preamble: whatever you want. From [PS3.10 §7.1](https://dicom.nema.org/medical/dicom/current/output/html/part10.html):

> This Part of the DICOM Standard does not require any structure for this fixed size Preamble.

The original intent was dual-format compatibility. You could stick a TIFF header in there, and the same file would open in both a DICOM viewer and an image editor. Clever interoperability trick from the 1990s. The spec even says that if you're not using the preamble, you "shall" zero it out. In practice, nobody validates this. Nobody checks. The 128 bytes just sit there, trusted.

After the preamble and prefix, the rest of the file is a flat stream of Tag-Length-Value (TLV) data elements. Same data model as the A-ASSOCIATE PDU from the 101, just serialized to disk instead of sent over TCP. Patient name, study date, modality type, pixel data. It's all TLV, all the way down. And none of it has integrity protection unless you explicitly opt into security profiles that the overwhelming majority of implementations don't support.

The spec itself now acknowledges this is a problem. A note in the current PS3.10 states that the file format "has a potential security vulnerability when the 128-byte File Preamble contains malicious executable content." CISA issued [ICS-ALERT-19-162-01](https://www.cisa.gov/uscert/ics/alerts/ICS-ALERT-19-162-01) over it. More on that in a moment.

## What the Spec Actually Offers for File Security

[PS3.15](https://dicom.nema.org/medical/dicom/current/output/html/part15.html) defines real security mechanisms for DICOM files. They exist. They're well-specified. Here's what's on the shelf:

**CMS Encapsulation (Media Security Profiles, Annex D):** The spec defines how to wrap a DICOM file in a Cryptographic Message Syntax envelope for confidentiality and integrity on removable media. AES encryption, the whole package. At the attribute level it's the `Encrypted Attributes Sequence (0400,0500)`. If that tag isn't present in a `.dcm`, there's no application-layer encryption on it. In the wild, files get dumped to USB sticks and network shares unencrypted.

**Digital Signatures (Annex C):** You can sign individual DICOM attributes or the full dataset using X.509 certificates and RSA. The spec defines four signature profiles: Creator RSA, Authorization RSA, Base RSA, and Structured Report RSA. Signatures land in the file as a `Digital Signatures Sequence (FFFA,FFFA)` containing the certificate, the signature bytes, and a timestamp. A conforming viewer is required to preserve those elements. It's not required to verify them. The granularity is the other problem: you choose which tags to sign, which means unsigned tags can be tampered with without breaking the signature. And the real blocker isn't the crypto: it's key distribution. Running a PKI across a hospital imaging network with devices from a dozen vendors, some of them running embedded OSes from 2012, is a genuine operational challenge.

**De-identification Profiles (Annex E):** PHI stripping for research use. Not encryption, not integrity, just attribute-level removal or replacement of identifying information. It falls apart on "burned-in" pixel data, where patient names are baked directly into ultrasound or fluoroscopy images as rendered text. The spec acknowledges this limitation and defines a "Clean Pixel Data Option," but implementing it requires image-level analysis that most de-identification tools skip.

Here's the thing: an [AJR article on DICOM security](https://www.ajronline.org/doi/full/10.2214/AJR.19.21958) said it plainly: the security features are in the standard, but most can't be used because manufacturers haven't implemented them. [MedCrypt's analysis](https://www.medcrypt.com/blog/why-secure-dicom-is-poorly-accepted-understanding-the-challenges) confirmed that vendor support and hospital deployment of secure DICOM has been "surprisingly limited." The DICOM working group (WG-14) has even proposed adopting the ACME protocol specifically to solve the key management problem that's blocked adoption for over two decades.

The spec did the work. The install base overwhelmingly hasn't deployed it. Partly because PKI in a hospital imaging network is genuinely hard. Partly because nobody's been forced to.

## Two Other Security Related Tags

Beyond the profiles, the spec defines two attributes in the [SOP Common Module](https://dicom.innolitics.com/ciods) that do useful security work on their own — and that almost nothing checks.

**SOP Instance Status `(0100,0410)`** carries a two-letter code: `NS` (Not Specified), `OR` (Original, not yet authorized), `AO` (Authorized Original, approved for diagnostic use), or `AC` (Authorized Copy). It's the spec's answer to "has this been signed off for clinical use." PACS accept and display all four states interchangeably. The flag exists. Nothing enforces it.

**Original Attributes Sequence `(0400,0561)`** is DICOM's audit trail. When an attribute gets modified — patient name corrected, study UID coerced during import — the prior value is supposed to land here with a modification timestamp, the modifying system, and a reason code (`COERCE` or `CORRECT`). If you pull a file from your PACS and this sequence is empty, you have no record of what the file looked like before it hit your network.

Open a random `.dcm` in [Innolitics' DICOM browser](https://dicom.innolitics.com/ciods) and look. The absence of these tags is the finding.

## DICOM Files as Malware Containers

### The Preamble Polyglot

Remember those 128 undefined bytes? In 2019, security researcher Markel Picado Ortiz (d00rt) at Cylera Labs demonstrated that you can put a valid PE (Windows executable) header in the preamble. The DOS header and stub fit in 128 bytes. The stub points to a PE payload stored further in the file inside a DICOM data element. The result is a single file that is simultaneously a valid `.dcm` and a valid `.exe`. Open it in a DICOM viewer: you see a medical image. Run it from `cmd.exe` and it executes as a Windows binary. The image stays clinically valid and viewable. This was assigned [CVE-2019-11687](https://www.cvedetails.com/cve/CVE-2019-11687/) (CVSS 7.8).

In April 2025, Praetorian extended this to Linux with ELFDICOM, demonstrating ELF-based polyglots and even a bash shebang variant that fits a shell payload in the preamble to download and execute a remote script. They also explored storing payloads beyond the 128-byte preamble constraint by placing executable data in DICOM data elements, effectively using the TLV structure itself as a payload container.

Researchers have demonstrated embedding full C2 implant binaries (Cobalt Strike beacons, Havoc payloads, arbitrary shellcode) into DICOM images while keeping the image intact and viewable. The clinical data is preserved. A radiologist reads the image and sees a normal scan. The malware is right there next to the patient's PHI.

### Why Antimalware Doesn't Catch It

Antimalware engines classify files by type. A file with a `.dcm` extension and a valid DICOM structure gets classified as a medical image. Benign. The scanner never parses the preamble as executable code because it doesn't think it's looking at an executable. Static analysis sees a DICOM image. The payload is there, intact, invisible to the scan engine.

Researchers have demonstrated that embedded payloads can evade static analysis in common antimalware tools. This isn't a bug in any particular AV product. It's a classification problem. The file is a valid DICOM image *and* a valid executable. The scanner picks one interpretation and misses the other.

### Beyond the Preamble

The preamble gets the headlines, but it's not the only hiding spot. The DICOM file format has several large, loosely validated binary containers that make excellent payload storage:

**Pixel Data `(7FE0,0010)`:** Encapsulated pixel data uses OB (Other Byte) value representation, which can hold arbitrary binary content in individual frames. Most viewers render the pixel data for display but don't validate the byte content of individual encapsulated frames. You can embed arbitrary data in frames that the viewer skips.

**Private Tags (odd-numbered groups):** The DICOM spec lets any implementation define proprietary data elements in odd-numbered groups. Conforming viewers are required to handle private elements they don't recognize, which in practice means ignoring them. D00rt's original PoC actually used a private group element `(0009,0000)` to store the PE payload. Arbitrary data, ignored by design.

**Overlay Data and Waveform Sequences:** Other large binary blobs defined in the spec that parsers rarely validate beyond their expected structure. More real estate for payloads.

A DICOM file is a container that every system in the imaging chain trusts and nobody validates at the byte level. That's the spec working as designed.

## Attack Scenarios

### C-STORE as a Delivery Mechanism

In the 101 I showed that getting past the A-ASSOCIATE handshake is often trivial when AE Titles are the only gate. Once you're in, you can C-STORE a weaponized `.dcm` to any accepting Storage SCP. The imaging network handles distribution from there. Modality pushes to PACS. PACS distributes to reading workstations. A single malicious file propagates through normal clinical workflow without any human action beyond the initial C-STORE.

### The DICOM Viewer as Attack Surface

DICOM viewers are typically medical-grade C/C++ applications with minimal sandboxing, parsing deeply nested TLV structures from untrusted input. Tag injection (unexpected Value Representations, oversized length fields, malformed sequences, recursive nesting) is classic parser bug territory. A crafted `.dcm` file doesn't need to carry an executable payload if it can trigger a buffer overflow in the viewer itself.

### Exfiltration via DICOM

Flip the attack direction. An attacker with access to a compromised workstation can embed stolen data (credentials, patient records, network maps) in private tags or unused pixel data frames, then C-STORE the file out to an external SCP. The firewall sees DICOM traffic on port 104. Looks like a normal study transfer. The exfiltrated data rides inside a valid DICOM image through a protocol that the network was built to allow.

### The Trust Chain Problem

Modalities are implicitly trusted by PACS. PACS is implicitly trusted by reading workstations and downstream systems. There's no file-level signature verification at any hop. No chain of custody. No content validation beyond basic DICOM conformance parsing. One compromised source (a modality, a media import station, a DICOMweb endpoint) poisons the entire downstream chain.

This is the structural problem. Individual attacks come and go. The trust model is the vulnerability.

## So What Do You Do About It

Network segmentation is table stakes, but it doesn't help once a payload is inside the imaging VLAN. If your defense stops at "we put the PACS on its own subnet," you're protecting the perimeter of a network that inherently trusts every file that flows through it.

**Validate the preamble on ingestion.** Every DICOM file entering your PACS should have its preamble checked. If it's not zeroed out and it's not a known safe format (TIFF dual-format for pathology whole slide imaging), strip it or reject it. The DICOM FAQ response to CVE-2019-11687 specifically recommends this. Media importers should already be doing it. Verify that yours actually does.

**Application-layer inspection of DICOM traffic.** Port-based firewall rules on TCP/104 tell you nothing about what's inside the PDUs. DICOM-aware inspection (parsing the C-STORE payload, validating against expected SOP classes, rejecting unknown private tags) is the equivalent of a web application firewall for imaging traffic.

**Push vendors on PS3.15 implementation.** The security profiles exist. Ask your PACS and modality vendors which PS3.15 profiles they support in their conformance statements. Most conformance statements don't mention security profiles at all. That silence is the answer, and it should be a procurement conversation.

**Build test files.** This is where tools like my Scapy DICOM module earn their keep. You can craft `.dcm` files with embedded payloads in the preamble, arbitrary data in private tags, and malformed TLV structures to test whether your defenses actually catch anything. If you're not testing with weaponized DICOM files, you don't know if your controls work. I'll cover that workflow in a future post.

## The File Format Is the Vulnerability

The DICOM Part 10 file format is a 30-year-old container designed to hold medical images. It turns out it holds malware just as well. The spec has the tools to address this: CMS encapsulation, digital signatures, TLS transport, preamble validation guidance. The industry hasn't deployed them, partly because PKI in a hospital imaging network is genuinely hard, and partly because nobody's been forced to.
