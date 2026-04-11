---
layout: post
title: "Medical Device Security: The IT vs OT Security Debate"
---

Medical device product security doesn't fit cleanly into a strict IT or OT security categorization — but if you had to say, they lean OT with IT assets. Let's break down why and where either analogy breaks.

![IT vs OT](https://www.jeffwinterinsights.com/s/IT-Vs-OT.jpg)

## The IT vs OT Baseline

IT security is confidentiality-first, data-centric, patch-friendly, and built around short hardware lifecycles. OT security flips the priorities: safety and availability come first, processes are sacred, change is dangerous, and assets live for decades.

## Why Med Devices Lean OT

Safety is the prime directive. Patient harm is physical, not just a data breach — the same mental model as process safety in industrial environments. Availability and integrity trump confidentiality.

Real-time operation constrains everything. Surgical imaging, infusion pumps, implantables — you can't patch and reboot during a procedure. Blocking data flow during surgery can kill.

Long lifecycles and difficult patching are the norm. 10–20+ year asset lives, embedded firmware, field-deployed devices you can't easily update, EOL operating systems. Classic OT problems.

These devices operate in somewhat managed physical environments — ORs, cath labs, patient homes — not open office floors. And critically, they actuate on the human body, functionally analogous to PLCs actuating on industrial processes, even though actual ICS hardware is mostly absent.

Hot take: the regulatory posture mirrors OT thinking too. FDA premarket guidance reads like IEC 62443 — threat models, secure update mechanisms, SBOMs. It treats devices like OT assets, not IT assets.

## Where Med Device OT Diverges From Industrial OT

Despite the OT lean, medical devices are a different animal from industrial control systems.

There's minimal to no ICS footprint. No SCADA, no historian, no DCS. You'll find occasional real-time controllers or small PLCs in capital equipment like surgical robots or imaging gantries, but it's the exception.

The Purdue Model doesn't apply in practice, though the conceptual layers translate somewhat well: field devices (embedded systems) → control systems (device subsystems and software processes) → supervisory (clinical workstations, mobile apps) → enterprise (EHR, PACS). The architecture isn't there, but the mental model is.

The "process" is a human body — non-deterministic, mobile, and protected by entirely different regulations (FDA, not NERC/CISA).

IT/OT convergence happens at the device itself, not at a DMZ. In ICS, convergence is at the boundary between corporate and plant networks. In med devices, convergence happens at the device — a PACS talking to a DICOM client, for example.

The threat actor economics are different too. Nation-state targeting a power grid vs. ransomware shutting down a hospital vs. targeted patient harm — very different risk profiles.

And regulation is device-centric, not facility-centric. IEC 62443 was designed to protect zones and systems; FDA guidance protects a product. The manufacturer owns the security story, not the facility operator.

## The IT Overlap

Med devices still carry significant IT DNA. Networking is pure IT — TCP/IP, TLS, PKI, DNS. These devices live on hospital enterprise networks. The protocols are IT-ish: DICOM, HL7, FHIR are application-layer protocols, not Modbus or OPC-UA. Software as a Medical Device (SaMD) can mean a cloud app with FDA oversight, which blurs the line heavily toward IT. Vulnerability management borrows IT tooling — CVEs, SBOMs, coordinated disclosure. Cloud connectivity, remote monitoring, OTA updates, and telehealth are all growing. Identity and authentication are IT disciplines through and through.

## Why This Matters

If you assume IT, you'll over-index on confidentiality and patching cadence and under-index on availability, safety impact, and change control. If you assume industrial OT, you'll reach for Purdue Models and ICS frameworks that won't map to your product architecture.

Medical device security is its own discipline — OT-flavored, IT-networked, safety-regulated. The right mental model: OT priorities with IT infrastructure and a unique regulatory wrapper (FDA + TIR57 + IEC 62443 applied at the product level) around everything.
