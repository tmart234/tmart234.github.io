---
layout: post
title: Cybersecurity Risk
---

I&#39;ve been contemplating Cybersecurity risk lately. I believe there are a lot of traps and misconceptions on the matter. I wanted to quickly go over some of those here….

First, the traditional formula:

**Risk = Impact\* Likelihood**

Now, you may disagree with that so get ready to disagree with a whole lot more.

Let&#39;s start with likelihood. This is typically the more controversial and political aspect of the traditional risk formula.

&quot;_What does likelihood mean, specifically for Cybersecurity risk? How can we define it?&quot;_

Cybersecurity risk, in particular, needs to deal with the case of the black swan one-time events. These events have high impacts and low likelihood. Such events could wipe out a company and be devastating.

Likelihood, in the case of Cybersecurity, therefore needs to reflect the likelihood, or probability, that a one-time event could occur. Likelihood to affect the organization once in 1,000 years. Likelihood to achieve the highest protection against evolving threats.

Threat actors exploit vulnerabilities with particular goals in mind and not simply because a vulnerability exists with a high CVSS score. So how can we gauge the likelihood of a one time event?

Context is key. CVSS is for measuring technical severity and not risk.

Temporal takes vulnerabilities factors into account, such as if the vulnerability is a &quot;zero-day&quot; or if mitigation is available. It could be further improved by capturing threat actors, threat intelligence, and other complexities of the real world.

Environmental scoring gets closer to the concept of risk by taking an asset&#39;s user context into the equation. For example, mitigations reflected in modified metrics and asset importance reflected in security requirement metrics. CVSS Environmental could further be improved by considering business risks, safety risks, and other user&#39;s environmental factors.

Quick recap:

If the attack is theoretical and not proven, this lowers the likelihood. If we have available mitigations to directly address the vulnerability, this lowers the likelihood. If we are patching software and managing risk in a mature manner, this lowers the likelihood. If the CVE is not actively being exploited by APTs in the wild, this lowers the likelihood.

Now impact.

While not as controversial as likelihood, I believe impact can have just as many issues.