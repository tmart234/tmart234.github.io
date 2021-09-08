---
layout: post
title: Cybersecurity Risk
---

I&#39;ve been contemplating Cybersecurity risk lately. Mostly shower thoughts. But I believe there are a lot of traps and misconceptions on the matter and I wanted to quickly go over some of those here…

First, the simplest formula:

**Risk = Impact \* Likelihood**

I want to acknowledge that everyone tends to define risk differently. Your CISO might think of impact in terms of Financial loss and QA might in terms of patient harm. 

As a security professional, you might want to complicate the formula even further because you read about it in some blog post:

**Risk = (Threat Actor Capability / Vulnerability Weakness) x likelihood x impact – control effectiveness**

But at the end of the day

**CVSS = Technical Severity**

and

**CVSS ≠ Risk**

See the whitepaper <a href="https://resources.sei.cmu.edu/asset_files/WhitePaper/2018_019_001_538372.pdf">Towards Improving CVSS.</a> Basically, the paper identifies 3 critiques for CVSS to resemble Risk: 
1. Failure to account for context (both technical and human-organizational). 
2. Failure to account for material consequences of vulnerability (whether life or property is threatened) 
3. Operational scoring problems (inconsistent or clumped scores, algorithm design quibbles)

## Failure to Account for Context

This is a good point to remind you that the real world can be complex. So is assessing risk.

CVSS Environmental v3.1 ONLY takes into account context of the user&#39;s assets, that is it! We can take into account context for the asset&#39;s mitigations in Modified metrics. We can also take into account for the importance of an asset, in terms of CIA, in Security Requirements. But keep in mind, CVSS was designed for assessing traditional IT assets, not everything under the sun. Therefore, environmental scoring gets slightly closer to the concept of risk by taking an asset&#39;s context into the equation. But that's not enough.

![CVSS risk attempt](/public/cvss-risk.PNG "CVSS risk attempt")

Unfortunately, we don&#39;t have context for how vulnerabilities can affect one another and be chained together. I imagine this would require a holistic view of all vulnerabilities in a system and mapping their complex relationships to things like ATT&CK patterns. I'll assume you already have a solution for this ;)

Next, we don&#39;t have context of how the vulnerability is being used in the wild or if it&#39;s actively being exploited. This could require gathering and utilizing threat intelligence, IoCs, classifying threat actors, a Business Impact Analysis, and participating in Information Sharing and Analysis Organizations. This context could be considered either vulnerability factors (temporal) or business risk factors (environmental).

Last, we have no context of how the system is being used in the real world and a consistent context throughout a community. Take the case of a hearing aid versus a pacemaker. They both have different context for their use cases. <a href="https://www.mitre.org/sites/default/files/publications/pr-18-2208-rubric-for-applying-cvss-to-medical-devices.pdf">MITREs Medical Device Rubric for CVSS</a> is an example of an attempt to harmonize context through out an industry. But remember, since CVSS only has context at an asset level, we fail to take into account the devices use case which ties into #2.

## Failure to Account for Consequences Either Life or Property

CVSS v4 is slated to add a safety metric. So this is a big win for Life. 

Although, a quick search of the word "property" in the CVSS CIGs working group's v4 Working Items resulted in 0 results. Not sure if this is to be considered but looks unlikely.

## Operational Scoring Problems

The CVSS formula was pulled from where the sun doesn&#39;t shine. There also wasn't solid empirical rational provided for the structure of the formula and the constant values of the formula weights.

## Likelihood

Let&#39;s dive into likelihood. This is typically the more controversial and political aspect of the traditional risk formula.

&quot;_What does likelihood mean, specifically for Cybersecurity risk? How can we define it?&quot;_

Cybersecurity risk, in particular, needs to deal with the case of the black swan one-time events. These events have high impacts and low likelihood. Such events could wipe out a company and be devastating.

Likelihood, in the case of Cybersecurity, therefore needs to reflect the likelihood, or probability, that a one-time event could occur. Likelihood to affect the organization once in 1,000 years. Likelihood to achieve the highest protection against evolving threats.

Threat actors exploit vulnerabilities with particular goals in mind and not simply because a vulnerability exists with a high CVSS score. So how can we gauge the likelihood of a one time event?

Context is key.

### Quick Recap:

If the attack is theoretical and not proven, this lowers the likelihood. If we have available mitigations to directly address the vulnerability, this lowers the likelihood. If we are patching software and managing risk in a mature manner, this lowers the likelihood. If the CVE is not actively being exploited by APTs in the wild, this lowers the likelihood.

## Impact

While not as controversial as likelihood, I believe impact can have just as many issues.