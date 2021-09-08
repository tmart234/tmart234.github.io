---
layout: post
title: Cybersecurity Risk
---

I&#39;ve been contemplating Cybersecurity risk lately. Mostly shower thoughts. But I believe there are a lot of traps and misconceptions on the matter. I wanted to quickly go over some of those here…

First, the traditional formula:

**Risk = Impact \* Likelihood**

Now, you may disagree with that and i&#39;d say to you: "buckle in for whole lot more".

**CVSS = Technical Severity**

and

**CVSS ≠ Risk**

See whitepaper "Towards Improving CVSS"

Basically, the paper identifies 3 critiques for CVSS to resemble Risk: 
"1) Failure to account for context (both technical and human-organizational). 
2) Failure to account for material consequences of vulnerability (whether life or property is threatened) 
3) Operational scoring problems (inconsistent or clumped scores, algorithm design quibbles)"

## 1) Failure to Account for Context

This is a good point to remind you that the real world can be complex. So can assessing risk.

CVSS Environmental v3.1 ONLY takes into account context the user&#39;s assets, that is it! Keep in mind, CVSS was designed for assessing traditional IT assets and not everything under the sun. We can take into account context for the asset&#39;s mitigations in modified metrics and we take into account for the importance of an asset in terms of CIA in Security Requirements. And that&#39;s it. 

Unfortunately, we don&#39;t have context for how vulnerabilities can affect one another and be chained together. I imagine this would require a snapshot and a holistic view of all vulnerabilities in a system before assessing which you have probably already done ;)

Next, we don&#39;t have context for how the vulnerability is being used in the wild. This could require gathering and utilizing threat intelligence, IoCs, classifying threat actors, a Business Impact Analysis, and participating in Information Sharing and Analysis Organizations. These could be considered vulnerabilities factors (temporal) or business risk (environmental).

Last, we have no context of how the system is being used in the real world and a consistent context throughout a community. Take the case of a hearing aid versus a pacemaker. They both have different context for their use cases.. Now MITREs Medical Device Rubric for CVSS is an example of an attempt to harmonize context through out an industry. They do a decent job at . But remember, since CVSS only has context at an asset level, we fail to take into account the devices use case which ties into #2.

## 2) Failure to Account for Consequences of Vulnerability Either Life or Property

CVSS v4 is slated to add a safety metric. So this is a big win for Life. A quick search of "property" in the CVSS CIGs working group's CVSS v4 Working Items resulted in 0 items.

## 3) Operational Scoring Problems

The CVSS formula was pulled from where the sun doesn&#39;t shine. There also wasn't solid empirical rational provided for the structure of the formula and the constant values of the formula weights.

## Likelihood

Let&#39;s dive into likelihood. This is typically the more controversial and political aspect of the traditional risk formula.

&quot;_What does likelihood mean, specifically for Cybersecurity risk? How can we define it?&quot;_

Cybersecurity risk, in particular, needs to deal with the case of the black swan one-time events. These events have high impacts and low likelihood. Such events could wipe out a company and be devastating.

Likelihood, in the case of Cybersecurity, therefore needs to reflect the likelihood, or probability, that a one-time event could occur. Likelihood to affect the organization once in 1,000 years. Likelihood to achieve the highest protection against evolving threats.

Threat actors exploit vulnerabilities with particular goals in mind and not simply because a vulnerability exists with a high CVSS score. So how can we gauge the likelihood of a one time event?

Context is key.

Environmental scoring gets closer to the concept of risk by taking an asset&#39;s user context into the equation. For example, mitigations reflected in modified metrics and asset importance reflected in security requirement metrics. CVSS Environmental could further be improved by considering business risks, safety risks, and other user&#39;s environmental factors.

### Quick Recap:

If the attack is theoretical and not proven, this lowers the likelihood. If we have available mitigations to directly address the vulnerability, this lowers the likelihood. If we are patching software and managing risk in a mature manner, this lowers the likelihood. If the CVE is not actively being exploited by APTs in the wild, this lowers the likelihood.

## Impact

While not as controversial as likelihood, I believe impact can have just as many issues.