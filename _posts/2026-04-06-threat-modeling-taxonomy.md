---
layout: post
title: Threat Modeling Generation Taxonomy
mermaid: true
---

All threat modeling methods define abstractions of reality; what differs is the entry point.

***"All models are wrong, some are more useful" - George E. P. Box***

In the threat modeling context, threats lead to potential (or unconfirmed) vulnerabilities ("a threat exploits a vulnerability"). The risk is not yet confirmed on our system, but rather in the wild. In other words: the output of threat modeling is a set of hypothesized attack scenarios that haven't been validated against a theoretical implementation yet.

When we say "centric", we are speaking to what is used as **input** to generate outputs (threats).

![Threat modelling approach]({{ site.baseurl }}/public/threat-modelling-approach.jpg)

## The Taxonomy

{% raw %}
<div class="mermaid">
graph LR
    subgraph Q1Q2["Q1+Q2: Scope, Enumerate, Invert"]
        direction TB

        subgraph inputs["Generative Inputs (enumerate → invert → threats)"]
            direction TB
            A["Asset-Centric<br>---<br>Crown jewels, services,<br>hardware, credentials,<br>dependencies, infrastructure"]

            subgraph systemmodeling["System Modeling (related but distinct)"]
                direction TB
                F["Flow-Centric<br>---<br>Data enumeration, DFDs,<br>trust boundaries,<br>data/control flows<br>(Structural - Spatial)"]
                P["Process-Centric<br>---<br>Operational workflows,<br>state transitions, CI/CD,<br>boot chains, provisioning<br>(Temporal - Sequential)"]
            end

            U["User-Needs-Centric<br>---<br>Feature to abuse inversion<br>User story threats<br>Feature-complete coverage"]
            ATK["Attacker-Centric<br>---<br>Threat actor profiles<br>Attack trees, PnG<br>(Domain-dependent)"]
        end

        subgraph generation["Threat Generation (the inversion)"]
            direction TB
            A_Q{{"What compromises<br>this asset's C/I/A?"}}
            F_Q{{"What crosses each<br>trust boundary?"}}
            P_Q{{"What breaks between<br>steps or workflows?"}}
            U_Q{{"How can this feature<br>be abused?"}}
            ATK_Q{{"What would THIS<br>adversary do to<br>our system?"}}
        end

        A --> A_Q
        F --> F_Q
        P --> P_Q
        U --> U_Q
        ATK --> ATK_Q

        A_Q --> T
        F_Q --> T
        P_Q --> T
        U_Q --> T
        ATK_Q --> T

        T["Raw Threats +<br>Documented Assumptions"]

        subgraph validation["Code-Centric Validation Layer"]
            direction TB
            C["Code Review<br>(Assumption Extraction)<br>---<br>What does the code believe?<br>Implicit trust relationships<br>Undocumented design beliefs"]
            DELTA["Assumption Deltas<br>---<br>Gaps between code reality<br>and model assumptions"]
        end

        T --> C
        C --> DELTA
        DELTA --> T2
        T2["Reconciled Threat<br>Inventory"]
    end

</div>
{% endraw %}

## A Note on STRIDE and the Four Questions

STRIDE can be used for both **generation** (as a methodology) and/or for **categorization** of threats depending on the centric method chosen. Make the distinction on how you're using it!

Shostack himself explained that the [four questions are not a specific methodology, but a foundation for a practical approach to threat modeling](https://threatmodel.buzzsprout.com/2152378/episodes/12826352-the-four-question-framework-with-adam-shostack).

These model-centric methods address both "what are we working on" and "what could go wrong."

## Asset-Centric

**To Start:** Enumerate crown jewel assets and work backwards to threats per STRIDE.

**Pros:** FAIR-style thinking. Translates well to DFD elements (processes, data stores). Impact-anchored. STRIDE-per-element.

**Cons:** Threat coverage is bounded by asset inventory. People and organizations are notoriously bad at asset inventory.

## Flow-Centric

**To Start:** Enumerate data, ask "how does the data move?" and draw the process/flow. Then draw the connecting DFD elements. Then enumerate elements with STRIDE.

**Pros:** STRIDE-per-interaction. Wide coverage.

**Cons:** Doesn't focus on emergent behavior. Flattens time to one flow.

## Process-Centric

**To Start:** Enumerate operational workflows and identify how an attacker would exploit that.

**Pros:** Threats are temporal and not structural (like flow-centric).

**Cons:** Dependent on process documentation or someone with process knowledge. May miss processes.

## User-Needs-Centric

**To Start:** Take a user story or need, apply an inversion lens, and generate threats from the abuse of that intended functionality.

**Pros:** Highly specific threat language. Feature-complete (harder to miss a feature) and exposes attack surface from features.

**Cons:** Needs asset context added -- when inverting a user story into an abuse case, you sometimes lack the right asset name or need more context on what's actually affected.

## Attacker-Centric

Attack trees are goal/adversary-centric: they answer *how* an attacker would actually realize a threat, not so much *what* threats exist. This approach works best when paired with high-priority threats.

**To Start:** Characterize your attacker's capabilities (e.g. APT28). From there, enumerate possible threats/attacks from their techniques, tactics, and procedures (TTPs).

**Pros:** Sophisticated security with layered detection.

**Cons:** Need enemies known, prioritized, and their capabilities assessed (e.g. TTPs).

## Code-Centric (Validation Layer Only)

*Note: This is a validation layer only, not a generative method. This is NOT "model-based" but implementation-based (non-theoretical). It doesn't replace the other methods; rather, it's the ground truth. Therefore, it can only validate or break all previous model-based assumptions or threat inventory.*

**To Start:** Use code reviews (including LLMs) to extract assumptions, not as a vulnerability hunt.

**Pros:** The only approach grounded in what actually exists. Maps best to CWEs. Can reveal things nobody documented (assets, processes, abuse cases).

**Cons:** Bottom-up -- produces findings, not a coherent threat narrative. Needs a model-layer lens for full context.

## Threat Output Characterization

CAPEC (design-level), CWE (code-level), ATT&CK (post-deployment/detection), CVSS, and even STRIDE are characterization layers of outputs, not input-centric threat generation methods.

## Supply Chain and Deployment

These aren't threats that need their own category; they're inputs to the previous methods that people just forget to enumerate. An Artifactory server is an asset -- you'd threat model it asset-centric. A CI/CD pipeline is a process. The gap isn't methodological -- it's an inventory problem.
