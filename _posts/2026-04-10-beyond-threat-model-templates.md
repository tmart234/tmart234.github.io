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

This one is for when the threat modeling team keeps using the same 2 mitigations for every threat. Threat modeling mitigations becomes a game of "what do we already have". Like an onion, security is in layers, and to have the most secure thing, you need security at all layers.

For example, if I have a browser application with threats, it's probably most ideal to have browser or application level mitigations. An OS level mitigation, while it may be relevant, would not be my first choice. Why? Because it wouldn't address the root cause. If the threat lives at the application layer, the mitigation should too. Stop slapping the same network firewall rule on everything and calling it a day.

### Religious zealot thinking and pedantic rationalization

Sometimes you teach someone how to rationalize cybersecurity risk just for them to use it against you: "we don't need to fix because this is not high risk". However true that may be, and sometimes it is true, if some risk is there at all and it's 2 Jira story points then why not fix? Low hanging fruit and priorities are hard to address holistically.

On the flip side, some security practitioners will fight you to the death on threats with physical attack vectors. And some practitioners will focus in so hard on physical that they forget remote attack vectors. Both extremes are dangerous. The zealot who dismisses everything below "critical" and the pedant who can't see the forest for the trees will both leave you with a threat model that doesn't reflect reality.
