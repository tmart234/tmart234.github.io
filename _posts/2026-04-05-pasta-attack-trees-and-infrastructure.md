---
layout: post
title: "PASTA, Attack Trees, Did We Do a Good Job, and the Infrastructure Nobody Built"
---

I've been kicking around some ideas on threat modeling lately -- scoring timing, PASTA's problem, where to start, and some project ideas that keep nagging at me. None of this is groundbreaking. Most of it is stuff the community has been circling for years.

## Scoring Vulnerabilities at the Wrong Time

CVSS assumes a vulnerability has already been discovered and verified. It's reactive by design -- you hand it a CVE and it hands you a number. CWSS operates earlier, at design time, scoring *weakness types* before they've manifested as specific vulnerabilities. This distinction matters more than people give it credit for.

If you're doing threat modeling during design -- which, if you're in medical devices under FDA premarket guidance or IEC 62443, you damn well should be -- CVSS doesn't help you yet. Now I'm not purposing you do anything today... but you don't have CVEs. You have CWEs. You have architectural assumptions that might be wrong. Systems like CWSS let you score those design-time weaknesses. CVSS makes you wait until someone finds the hole. But that doesn't make CWSS the best alternative.

And then there's SSVC -- CISA's Stakeholder-Specific Vulnerability Categorization. SSVC doesn't give you a number. It gives you a *decision*: track, attend, or act. That's fundamentally different. CVSS tells you how bad something is on a scale. SSVC tells you what to do about it. The real automation opportunity isn't calculating scores faster -- it's automating the decision tree. For medical devices, tying SSVC's exploitation status and mission impact to your device's clinical context would actually be useful. A 7.5 CVSS on a surgical imaging system during a procedure is not the same as a 7.5 on a back-office analytics dashboard. The score is identical. The decision should not be.

## Where You Start Determines Where You End Up

Not all threat modeling starting points are equal. Threats don't look the same across fintech, OT, and hospitals -- and your entry point into the process shapes what you find.

### Start from what you're building (do this)

DFDs, system decomposition, trust boundaries. You know your own system better than you know anything else. This is STRIDE's natural home. Decompose the thing, ask what can go wrong at each boundary, and you'll find real problems. It's not glamorous, but it works. And it works repeatably, which is half the battle.

### Start from assets (tempting, often a trap)

Asset-centric modeling can be attractive -- "we have PHI, therefore threats." But it tends to pull you away from the actual goal of threat modeling and into what is essentially a risk assessment wearing a threat model's clothes. You end up cataloging value instead of finding flaws. I've [written about this before](https://tmart234.github.io/beyond-threat-model-templates/) -- templates that are purely asset-centric will never capture business context, and without business context, your threats won't speak to business risk. Assets are context, not the starting line.

### Start from attackers (don't do this)

We are not James Bond. We know less about our adversaries than we know about the systems sitting on our desks. Attacker-centric modeling requires threat intelligence most teams don't have, and it biases you toward Hollywood scenarios -- nation-state actors and zero-days -- while the actual breach comes from a misconfigured service account. Starting from the attacker is starting from ignorance and calling it strategy.

### Be specific about threats, vague about actors

Here's a nuance that doesn't get enough airtime: be precise about *what* the threat is, and deliberately vague about *who* performs it. "An unauthenticated network actor replays a DICOM C-STORE" is useful. "A nation-state adversary targets our surgical imaging platform" is theater. Threat actor attribution and motive speculation waste time and, worse, they narrow your threat coverage. If you model only for the sophisticated attacker, you miss the script kiddie who walks through your open door.

## PASTA: The Kitchen Sink Framework

PASTA (Process for Attack Simulation and Threat Analysis) feels like it was created by and for a CISO. It tries to be everything -- asset-centric, business-centric, risk-centric, threat-centric, attacker-centric -- and in trying to be everything, it becomes the kitchen sink. It is not optimized. It's easy to get lost in the sauce (pun intended) because the framework conflates multiple activities that each deserve their own focus.

PASTA uses attack trees, DFDs, and threat intelligence across seven stages:

1. Define objectives (asset and business impact analysis)
2. Define technical scope (components)
3. Application decomposition (DFD model)
4. Threat enumeration and analysis
5. Vulnerability assessment
6. Attack tree and attack enumeration
7. Countermeasures and residual risk

Seven stages. And most teams stall somewhere between Stage 4 and 5 because they lack the threat library and vulnerability mapping infrastructure to actually execute. The framework assumes a level of organizational maturity and bandwidth that most product security teams simply don't have. It's not that the ideas are wrong -- they're not. It's that the framework isn't designed for the team of three trying to ship a threat model before the next design review.

### What PASTA Gets Right

The attack tree hierarchy is genuinely powerful:

**Asset --> Use Case --> Threat --> Abuse Case --> Vulnerability (CWE) --> Attack Pattern (CAPEC) --> Impact**

That's a traceable chain from business value down to testable attack scenarios. It's exactly the kind of traceability that FDA expects in a premarket submission, and it maps cleanly to tools like Polarion. If you can build this chain and maintain it, you have something real.

Attack conceptualizing -- building a threat library, mapping a vulnerability library that realizes those threats, then mapping attack patterns to determine viability -- is the intellectual core of PASTA. And it's the part most people skip because the tooling doesn't exist.

**Note: attack patterns are not threat libraries.** CAPEC entries describe *how* an attack is executed. They are not threats themselves. A threat library describes *what can go wrong*. Attack patterns describe *how someone makes it go wrong*. Conflating the two is a common mistake and it makes your threat model simultaneously too specific (tied to particular attack techniques) and too vague (missing the broader threat context).

## Ideas

### CWE <-> CAPEC Mapping

MITRE publishes these relationships, but they're buried in XML that nobody wants to parse over their morning coffee. A clean, queryable database -- even SQLite -- that maps CWE weaknesses to their realizing CAPEC attack patterns and back would directly enable the PASTA Stage 5-->6 transition that most teams can't execute today.

The pipeline: **CAPEC property --> threat logic --> threat model element.** If you have a threat library with threat logic derived from CAPEC, you can programmatically derive threat model elements from that logic. And if you look up each element in a database rather than a flat file, you can include diagrams, code examples, and other metadata that make the output actually useful rather than just technically correct.

Of the ideas here, this one nags at me the most because the others kind of depend on it.

### GitHub-Based PASTA Attack Trees

Version-controlled attack trees make sense for collaboration and review. The [CNCF Financial User Group's K8s threat model](https://github.com/cncf/financial-user-group/tree/master/projects/k8s-threat-model/AttackTrees) uses a similar approach and is worth studying before building your own.

One caveat: markdown attack trees get unwieldy past about three levels of depth. A structured format -- YAML or JSON -- that *renders* to visual trees would age better. The source of truth should be machine-readable; the pretty picture should be generated.

### Attack Tree --> TMT Template File

Microsoft's Threat Modeling Tool uses `.tm7` XML template files. Programmatically generating threat template entries from the CWE/CAPEC database would let you push curated, domain-specific threats directly into TMT. Essentially: build a medical device threat template that is traceable to CAPEC, and distribute it as a `.tm7` file that any team can import. This bridges the gap between a research database and a tool that practitioners already have on their machines.

### Adding Business Context

This is the hardest and most important problem. My suggestion: model business context as a thin metadata layer on top of your attack trees. Clinical impact severity, patient safety relevance, regulatory applicability (FDA device class, IEC 62443 security level). Don't try to embed full business logic into the tree -- tag the nodes so stakeholders can filter by what matters to them. The tree stays technical. The tags make it legible to everyone else.

## "Did We Do a Good Enough Job?"

This question can be answered simply: is there still work from the other three questions to be done? If yes, then no, you didn't do a good enough job. It sounds circular but it's actually a useful heuristic. If you still have unexamined components, unidentified threats, or unaddressed findings, you're not done. The threat model is complete when it stops producing actionable work.

## The Stakeholder Problem

*"The outcomes of threat modeling are meaningful when they are of value to stakeholders."*

Sometimes a short sentence says a lot. Two takeaways:

First, tailoring threats to match business risk, product domain, and the actual deployment environment provides some of the best value you can deliver. A generic threat model template will never get you there. You need tailored outputs. This is why I've been beating the templates drum for years and why I now [go beyond them](https://tmart234.github.io/beyond-threat-model-templates/) -- templates are the floor, not the ceiling.

Second, do you actually have all your stakeholders identified and participating? For medical devices, your stakeholders span engineering, clinical, regulatory, quality, and often the hospital IT and security teams who will deploy and maintain the thing. Threat modeling outputs need to speak to all of them. Pure engineering frameworks like STRIDE alone don't speak business. Pure business frameworks like PASTA alone overwhelm engineers. Neither is sufficient without adaptation, and adaptation requires knowing who's in the room and what they need from you.

## Maturity Models: BSIMM and OpenSAMM

BSIMM (Building Security In Maturity Model) and OpenSAMM are maturity models, not threat modeling methodologies. Don't confuse the two. They answer "how mature is our overall secure software development lifecycle?" BSIMM has PASTA mappings, which is interesting -- it means you could show where something like a CWE/CAPEC database or attack tree workflow fits into a recognized maturity framework. Useful when you're trying to get budget. Leadership doesn't fund threat libraries. They fund maturity improvements. Learn to speak their language.
