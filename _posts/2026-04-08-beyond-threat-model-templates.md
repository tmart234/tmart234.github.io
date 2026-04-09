---
layout: post
title: Beyond Threat Model Templates
---

My viewpoint on threat modeling has matured since my [last post on templates](/threat-model-template/). Recently, I have been using a combination of template threat modeling, combined with process and user-needs threat modeling with some GenAI sprinkled in to help out. If you're not familiar with template threat modeling, check out [my other post](/threat-model-template/).

## Faults of Templates

First, threat model templates are great and I definitely encourage you to try and use them in some way that suits you. But they don't address the whole picture of what is "all potential threats".

Pretty soon after I posted about templates, I started to see where and why they lack. The biggest issue is they ONLY address asset-centric threats and therefore templates will never contain business related context. And without business context, the resulting threats will never speak to business risk. The asset-centric threats can however speak to regulatory risk well, but as you probably already know, threat modeling is much more than just a compliance activity.

The problem with being confined to an asset-centric approach is that you can only infer: "because we use asset x, we have threat y". In a template, this would be your threat generation logic. But you can't infer more specific threats like "because the user can do x, someone could abuse it like y".

My mature viewpoint is that business risk is essential to capture if you want the whole picture. I've learned the hard way that a threat with business risk will sell a lot easier to your audience in threat modeling meetings because your audience (likely) understands business context. And selling the threat means you have a higher chance of fixing things.

Another annoying thing is that templates can be very painful to maintain, and if not scaled to an incredibly large scale, the amount of maintenance they take usually doesn't pay off.

## My New Approach

The faults above led me to stop relying on templates alone and start combining multiple threat generation methods. I wrote up the full picture in my [Threat Modeling Generation Taxonomy](/threat-modeling-taxonomy/) post. The short version: instead of only using asset-centric template generation, I now combine it with process-centric and user-needs-centric approaches. The taxonomy explains each method, when to use it, and how they complement each other.

Templates still have a role. They're the starting point for asset-centric coverage. But if you stop there, you're leaving business risk, abuse cases, and workflow threats on the table.

## Pitfalls, Double Edge Swords, Booby Traps

### Fix shit at the affected asset's layer, for Christ sake

This one is for when the threat modeling team keeps using the same 2 mitigations for every threat. Threat modeling mitigations becomes a game of "what do we already have." That's not risk reduction -- that's asset inventory with extra steps. Like an onion, security is in layers, and to have the most secure thing, you need security at all layers. This is especially true for network-connected devices where the attack surface spans from firmware to cloud.

For example, if I have a browser application with threats, it's probably most ideal to have browser or application level mitigations. An OS level mitigation, while it may be relevant, would not be my first choice. Why? Because it wouldn't address the root cause. If the threat lives at the application layer, the mitigation should too. Stop slapping the same network firewall rule on everything and calling it a day.

Even worse is outsourcing the mitigation to the customer entirely. "Just put it on a secure network" is not a mitigation you own -- it's a mitigation you hope someone else implements. If your threat lives in the application and your answer is "the hospital network will handle it," you've shipped a vulnerability and called it a recommendation. Own the fix at the layer where the problem lives.

### Religious zealot thinking and pedantic rationalization

Sometimes you teach someone how to rationalize cybersecurity risk just for them to use it against you: "we don't need to fix because this is not high risk." However true that may be -- and sometimes it is true -- if some risk is there at all and it's 2 Jira story points then why not fix? This gets worse when teams hide behind CVSS scores as gospel. A medium-severity finding gets deprioritized because the number says so, even when context says otherwise. CVSS measures technical severity, not business risk. I've [written about this before](/cyber-risk/) -- the score is a starting point, not a verdict.

The low-hanging fruit argument cuts both ways. "It's low risk so why bother" sounds rational until you have a dozen low-risk findings that collectively paint a different picture. Attackers chain weaknesses. They don't filter by severity. If the fix is cheap and the risk is real, ship it.

On the flip side, some security practitioners will fight you to the death on threats with physical attack vectors. And some practitioners focus so hard on physical that they forget remote attack vectors entirely. Both extremes are dangerous. The zealot who dismisses everything below "critical" and the pedant who can't see the forest for the trees will both leave you with a threat model that doesn't reflect reality. Balance means considering the full spectrum -- from someone with a USB stick in a server room to a remote attacker on the other side of the world -- and weighting it by what's actually plausible for your environment.

### No corrective action, no learning

Threat modeling without a feedback loop is a one-time exercise. You generate threats, propose mitigations, file some Jira tickets, and move on. Six months later, no one checks whether those mitigations were actually implemented or whether they worked. In regulated industries this has a name -- CAPA (Corrective and Preventive Action) -- and it exists because learning from what went wrong is how you prevent it from happening again. Threat modeling needs the same discipline.

What I've seen happen repeatedly: security requirements get written into the design, then quietly descoped when the project timeline slips. A PMO cuts the security story because it's not "customer-facing." The threat model said it mattered, but nobody traced the requirement back to the threat. Without that traceability -- from threat to requirement to implementation to verification -- you can't prove the threat was addressed. And if you can't prove it, assume it wasn't.

The fix is straightforward even if it's not easy: treat threat model outputs like requirements, track them in whatever system your team already uses, and review them at milestones. If a mitigation gets cut, that's a risk acceptance decision -- make someone sign their name to it. Feedback loops turn threat modeling from a checkbox into a living process.
