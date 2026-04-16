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

### No CAPA for threat modeling

When a threat model proposes a mitigation, there's no corrective action process to make sure that fix actually happens. In a quality system, you'd write a CAPA -- document the issue, assign the fix, verify implementation, confirm it worked. Threat modeling doesn't have that. Someone files a Jira ticket and the mitigation is out there competing with feature work, subject to prioritization by people who weren't in the room when the threat was identified.

So security requirements become negotiable scope. The PMO cuts certificate pinning to hit a release date. Nobody traces that cut back to the threat it mitigated. Nobody formally accepts the residual risk. Nobody signs their name to that decision. The requirement just disappears and everyone pretends the threat went with it. The threat model itself became theater the moment the mitigations became negotiable scope.

Then there's chaining -- the thing your risk matrix will never catch because it evaluates everything in isolation like security is a checklist instead of a system. Five lows in the backlog, each individually "accepted" because they scored below the threshold. String three together and you've got a credible attack path walking through your architecture. Security is a process, not a product, and a process means understanding how small weaknesses compose into catastrophic ones. Without periodic reassessment of the aggregate picture, accepted lows pile up until they're somebody else's incident.

The fix is traceability. Threat to requirement to implementation to verification. If a mitigation gets cut, that decision traces back to the threat and someone with authority formally accepts the risk. When a pentest finding maps to a threat that was already modeled with a mitigation that got descoped -- that needs a corrective action. Why was it cut? What's systemic? How do we prevent it next time? Without that loop, threat modeling is security theater with a spreadsheet.
