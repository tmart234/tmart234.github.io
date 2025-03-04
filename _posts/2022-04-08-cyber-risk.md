---
layout: post
title: Cybersecurity Risk
---

I wanted to discuss some shower thoughts that I've had recently around how we perceive Cybersecurity risk. I recognize that the subject of cybersecurity risk is not very sexy. So being my first post, I gave the blog a HOT title.

First, if you haven't already, check the whitepaper <a href="https://resources.sei.cmu.edu/asset_files/WhitePaper/2018_019_001_538372.pdf">Towards Improving CVSS.</a> 
TL;DR: of the paper is it identifies 3 critiques for CVSS to resemble Risk: 
1. Failure to account for context (both technical and human-organizational). 
2. Failure to account for material consequences of vulnerability (whether life or property is threatened) 
3. Operational scoring problems (inconsistent or clumped scores, algorithm design quibbles)

You can also optionally check out <a href="https://bit.ly/cvssv4-workitems">A List of potential improvements for CVSS v4</a>. We will cover some of these within this post but note that the v4 improvements contain the <a href="https://resources.sei.cmu.edu/asset_files/WhitePaper/2018_019_001_538372.pdf">Towards Improving CVSS</a> article referenced above.

I have scored with CVSS a bit but only started really digging into the issue after I stumbled on an interview with Art Manion, one of the original creators of CVSS. When asked how CVSS was formulated, what <a href="https://searchsecurity.techtarget.com/news/252458370/CERT-CCs-Art-Manion-says-CVSS-scoring-needs-to-be-replaced">  he had to say </a> was quite alarming: “The math is sort of tortuous. There wasn't a lot of transparency on that process. I'm on the SIG, so I actually know a little bit about what happened, but no one else really does. We didn't even write it down that well internally, so it's hard to tell.”

Wow! So answering questions like "Why is "Local"  for Attack Vector equal to 0.71" is impossible to answer because no "one wrote it down". So not only are people confusing CVSS for a real risk analysis, but we don't have sound reasoning for it's formula and values.

... Okay then what is risk?
From a non-cybersecurity perspective, the simplest formula typically used is:

**Risk = Impact x Likelihood**

I want to acknowledge that everyone tends to define risk differently. Your CISO might think of impact in terms of Financial loss and QA might in terms of patient harm. 

As a security professional, you might want to redefine the formula even further because you slightly read into it for a CISSP exam:

**Risk = (Threat Actor Capability / Vulnerability Weakness) x Likelihood x Impact – Control Effectiveness**

But at the end of the day

**CVSS = Technical Severity**

and

**CVSS ≠ Risk**

Or at least that's how things currently stand...

## Failure to Account for Context

This is a good point to remind you that the real world can be complex. So is assessing risk. Particularly because we are accounting for real world context and there are endless ways to do this.

CVSS Environmental v3.1 ONLY takes into account context of the user's assets, that is it! We can take into account context for the asset's mitigations in Modified metrics. We can also take into account for the importance of an asset, in terms of CIA, in Security Requirements. Therefore, environmental scoring gets slightly closer to the concept of risk by taking an asset's context into the equation. But that's not enough. Also keep in mind, CVSS was designed for assessing traditional IT assets, not everything under the sun. 

![CVSS risk attempt](/public/cvss-risk.PNG "CVSS risk attempt")

Unfortunately, we don't have context for how vulnerabilities can affect one another and be chained together. I imagine this would require a holistic view of all vulnerabilities in a system and mapping their complex relationships to things like ATT&CK patterns. There are vendors working hard on vulnerability chaining using ML/AI solutions with automated testing.

Next, we don't have context of how the vulnerability is being used in the wild or if it's actively being exploited. This could require gathering and utilizing threat intelligence, IoCs, classifying threat actors, or a Business Impact Analysis. This context could be considered either vulnerability factors (temporal) or business risk factors (environmental). Focus should be shifted to the skills and motivations of an attacker, and whether the effort required to exploit a vulnerability is less than the perceived gain the attacker will achieve by compromising the system rather than focusing on attempting to quantify likelihood of a future adverse impact in traditional probabilistic terms.

Last, we have no context of how the system is being used in the real world and a consistent context throughout a community. Take the risk cases of a hearing aid versus a pacemaker. They both have different context for their use cases. <a href="https://www.mitre.org/sites/default/files/publications/pr-18-2208-rubric-for-applying-cvss-to-medical-devices.pdf">MITREs Medical Device Rubric for CVSS</a> is an example of an attempt to harmonize context throughout an industry. But remember, since CVSS only has context at an asset level, we end up with a decent asset analysis but fail to take into account the device use case and other environmental factors which will tie into #2.

## Failure to Account for Consequences Either Life or Property

CVSS v4 has purposed to add a safety metric. So this is a big win for accounting for patient harm and loss of life. Beyond medical, automotive, Operational Technology, and aerospace industries could benefit from this metric.

Although, a quick search of the word "property" in the CVSS CIGs working group's "v4 Working Items" resulted in 0 results. Not sure if this is to be considered but looks unlikely.

## Operational Scoring Problems

To put it nicely, the CVSS formula was pulled from where the sun doesn't shine. There was never any solid empirical rational provided for the structure of the formula or for the constant values of the formula weights. The paper calls for a complete overhaul in the formula and goes over an effective approach to do so. 



## Likelihood

Let's dive into likelihood. This is typically the more controversial and political aspect of the traditional risk formula.

"What does likelihood mean, specifically for Cybersecurity risk? How can we define it?"

### Definitions
- ISO 31000 defines likelihood as:“the chance of something happening.”
- NIST 800-30: “the probability that a given threat is capable of exploiting a given vulnerability or a set of vulnerabilities.”
- AAMI TIR57 Risk Management Principles for Medical Device Security & CNSSI No. 4009 defines likelihood of occurrence as: “weighted factor based on a subjective analysis of the probability that a given threat is capable of exploiting a given vulnerability”


Safety risk management is designed to deal with failures in which the likelihood is based on design and manufacturing factors. Whereas security risk management likelihood is more of an estimate to whether an attacker will invest time and resources to exploit that vulnerability.

Cybersecurity risk, in particular, needs to deal with the case of the black swan one-time events. These events have high impacts and low likelihood. Such events could wipe out a company and be devastating.

Likelihood, in the case of Cybersecurity, therefore needs to reflect the likelihood, or probability, that a one-time event could occur. Likelihood to affect the organization once in the entire product lifetime. Likelihood to achieve the highest protection against evolving threats.

Threat actors exploit vulnerabilities with particular goals in mind and not simply because a vulnerability exists with a high CVSS score. So how can we gauge the likelihood of a one time event?

Context is key.

### Quick Recap:

If the attack is theoretical and not proven, this lowers the likelihood. If we have available mitigations to directly address the vulnerability, this lowers the likelihood. If we are patching software and managing risk in a mature manner, this lowers the likelihood. If the CVE is not actively being exploited by APTs in the wild, this lowers the likelihood.

## Impact

While not as controversial as likelihood, I believe impact can have just as many issues. 

Let's start we the fact that we are using CIA as a means to gauge impact. The lack of granularity in just high, medium, and low metrics can present a challenge for achieving accurate CIA values.

Next, the fact that every company has different operating factors, and maturity levels, and their own interpretations can lead to a different risk environment at the organizational level.

Now let's look at the CVSS Environmental formula to see how Security Requirements are used: 
** 1 - [ (1 - ConfidentialityRequirement × ModifiedConfidentiality) × (1 - IntegrityRequirement × ModifiedIntegrity) × (1 - AvailabilityRequirement × ModifiedAvailability) ]**

Unfortunately, with Security Requirements are only gauging impact at the asset level, we have no context of vendor or regulatory risk levels. If the vendor only designs class 3 implants, it would probably have a high organizational and regulatory risk. If regulatory had strict requirements, this would be high regulatory risk. Ultimately this is NOT the vendors decision.

On top of all that, we also lack ways to determine Security Requirements based on Threat Actor Risk in a given environment.

So perhaps we can say an asset's individual impact is something like:

**(IR x CR x AR) = Asset Impact**

And when we combine all of the new environmental impacts in a some meaningful way we get:

**(Asset Impact + Organizational Impact + Regulatory Impact + Threat Impact) = Environmental Impact**

This new Environmental impact would be more encompassing beyond just the individual asset level.
I suggest we focus on creating repeatable frameworks for deriving Security Requirements so that companies can factor this into their risk analysis.

## Other Scoring Specs

EPSS takes complexity and how the vulnerability is being exploited into account. So does VPR, which is maintained by tenable. I personally like VPR.

Metrics in VPR are: Vulnerability Age, CVSS Impact, Exploit Code Maturity (CVSS), Product Coverage (similar to target distribution), Threat Sources, Threat Intensity (or frequency), and Threat Recency (in days)

SSVC is another decent risk scoring spec. CVSS's mathematical inputs are vectors which have a direction and magnitude. The formula gets evaluated with curve fitting math which outputs a reduced partial range. SSVC uses decision points as inputs and evaluates with decision trees that outputs a qualified priority. Decision trees are qualitative actions that an organization can take. SSVC uses 6 decision point categories: exploitation (threat feed), technical impact (cvss base), utility, exposure, mission impact, and safety impact. Exposure, mission impact, and safety impact can all be asset management.

## CVSS v4

Let's dig into CVSS <a href="https://docs.google.com/document/d/1qmmk9TQulW9d1cuipu_ziXDX0pUswbZ1WSQyynHbvKU/edit">v4 working items.</a>


### Threat Metric Group
Temporal Metric Group is replaced with Threat Metric Group as the SIG focuses on the importance of using Threat Intelligence for accurate scoring. An additional Threat Intelligence metric has been purposed. On top of that, there is pending removal of Report Confidence and Remediation Level metrics. Any previous temporal exploitability metrics should go into base.


### Environmental
Representation of vendor-supplied Severity/Impact scoring within CVSS standard. This is interesting because Security requirements reflect asset importance, whereas vendor-supplied Severity reflects the vendor’s risk level. Lastly, we would still need an industry or regulatory defined risk level to get full context of Environmental Impacts.

Target distribution to be added back. Similarly used in such scoring metrics like Vulnerability Priority Rating (VPR).



The working items mentions the “Towards Improving CVSS.” whitepaper at the end and acknowledges a shift needed to focus on deciding response priority, which is more like risk than severity.



