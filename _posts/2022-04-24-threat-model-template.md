---
layout: post
title: Threat Modeling Knowledge Bases and Templates
---

# Threat Modeling Knowledge Bases and Templates

A mix of frustrations, aspirations, and unsolicited opinions regarding the current state of Threat Modeling are initially what prompted me to write this post.

First some clarification up front. When I talk about threat model templates, threat knowledge bases, or custom threat lists then I’m roughly talking about the same thing. Threat knowledge bases are a database of pre-defined threats that capture the current threat landscape. The more precise a knowledge base aligns with your model’s use case, then the higher value it provides. Templates usually include a knowledge base while also including other things like the DFD elements, their properties, and logic to tie knowledge base with the DFD elements.

## Pain Points

Threat Modeling, which is arguably the most fundamental and important Software Security Development Lifecycle (SSDL) activity, is far from a matured process. First, there is a lack of any useful + free tooling that facilitates the process entirely end-to-end. Next, all modeling practitioners have different methods, which are implemented with segregated and specialized knowledge. This makes facilitating the process end-to-end extremely difficult. Lastly, the execution of the activity can take a large amount of time and effort for the multiple parties engaged. This does not make sense from a cost/benefit perspective, especially if your team is attempting threat modeling for the first time!

Threat Modeling may seem ancient, decrepit, or somehow still better on a whiteboard. Due to this, it is continually being required by [more ](http://www.imdrf.org/docs/imdrf/final/technical/imdrf-tech-200318-pp-mdc-n60.pdf)and [more](https://www.fda.gov/regulatory-information/search-fda-guidance-documents/content-premarket-submissions-management-cybersecurity-medical-devices) guidance, as well as the fact that more regulatory agencies are demanding to see a threat model.

Some issues Threat Modeling faces are as such:

- *How do we make Threat Modeling highly repeatable?*
- *How can an enterprise produce Threat Models at scale?*
- *How can the modeler deal with a constantly changing threat landscape?*
- *How can the completion of Threat Modeling be less reliant on hiring a 3rd party consultant who is in tune with that threat landscape? (not just for specialists)*
- *How can the newly hired security professional effectively produce a Threat Model of value?*
- *How can a small startup, with no dedicated security personnel, quickly produce a Threat Model of value?*

I believe the answer to all these questions lies in threat modeling templates. 

Let me explain...

## What Works For Me May Not Work for You

Before I begin, I must say this caveat: what is presented in this blog reflects my particular views and opinions of Threat Modeling. These views should not be taken as prescriptive advice on “how to Threat Model'', nor do these views reflect that of my employer. This is more so a reflection of opinion on the matter.

***“All models are wrong, some models are useful” - George E. P. Box, British statistician***

I personally find threat modeling with data flow diagram (DFD) templates to be extremely useful and if you find value in them too, then that’s great! Hopefully you find this post informative.

## The Problem

At a high level, the problems with Threat Modeling can be distilled down to lacking 3 basic concepts:

1. Repeatability
1. Consistency
1. Simplicity

All three, when combined, can begin to achieve scalability. So, let’s dive into each.

## Repeatability

Repeatability is desired in order to produce the same high quality product over time. To make Threat Modeling highly replicable, we are able to create a model from a template. 

` `A Threat Model DFD template contains the following:

- A library of non-generic DFD elements (called stencils in MS TMT) and their custom properties
  - [Generic Threat Modeling elements](https://en.wikipedia.org/wiki/Threat_model#Visual_representations_based_on_data_flow_diagrams) are: datastores, flows, processes, external interactors, and boundaries
- A non-generic library of threats and their custom properties
  - Generic Threat Modeling threats can that of [STRIDE](https://en.wikipedia.org/wiki/STRIDE_\(security\)) or another methodology
  - Threat properties usually includes threat logic
    - Ex: ‘Flow is HTTP’

“In a nutshell, Templates are stripped-down Threat Models”, which don’t contain any diagram level information. “You can consider them as highly-specialized knowledgebases, and you can combine them to create your specific context”. [Well said Simone](https://www.google.com/amp/s/threatsmanager.com/2020/11/21/threat-modeling-with-tms-diagramming/amp/), creator of Threat Manager Studio.

Templates provide a repeatable way for anyone to begin to address what they are working on and what could go wrong. Simone has a few interesting blog posts on designing and maintaining Microsoft threat model templates (see [starting](https://simoneonsecurity.com/2016/09/04/tm-templates-1/), [stencils](https://simoneonsecurity.com/2016/09/10/threat-modeling-templates-the-stencils/), [threats](https://simoneonsecurity.com/2016/10/02/threat-modeling-templates-the-threats/), [properties](https://simoneonsecurity.com/2016/10/18/threat-models-template-the-properties/)). But these were written 5 years ago when Microsoft released the 2016 version of the tool and sadly, templates didn’t catch on. 

## Consistency

Threat logic should be configurable and simple. If using a methodology, like STRIDE per-element, every threat’s logic condition is checked for every diagram’s element. If logic conditions for the threat are satisfied, then it qualifies as a generated threat, and should show up in the generated threat list.

Let’s run through a hypothetical, yet trival, example to put everything into perspective:

Say you have a template for AWS (Amazon Web Services). That template has a non-generic datastore element called “S3 bucket”. That S3 bucket element has a unique element property called “is public”. The threat logic can be something simple like: “S3bucket.is\_public is ‘yes’”. Now when the modeler has the AWS template applied, uses the S3 bucket element, and then sets the “is public” property to yes, then the model will generate a non-generic information disclosure threat titled something like “An adversary gains access to data within a public S3 Bucket”.

Some have described the Threat Modeling process as: 

- Identify Assets 
- Create an Architecture Overview 
- Decompose the Application
- Identify the Threats 
- Document the Threats 
- Rate the Threats

![](C:\Users\tmart\AppData\Local\Temp\Rar$DIa8088.29437\Aspose.Words.d7d60446-8d49-4518-aaff-70b783b4708c.001.png)

If using consistent architecture, and threat model templates that contain that architecture, the “Create Architecture Overview” step has been taken care of upfront. The Architecture is now all the non-generic elements within the template available for the model practitioner. Also, by building a template with a non-generic list of threats and using threat generation, the “Identifying Threats” phase of the process has been abstracted. This is because all relevant threats and logic are recorded within the template’s knowledgebase then generated within the model.

## TM Tooling’s Role in Templates

***Templates provide a map that enables the model practitioner to navigate a complex threat landscape***

Threat Model tooling should never be responsible for producing templates themselves. Rather, this should be provided by the companies, working groups, and specialists, as the tool simply couldn’t cover every domain. Some tooling tries to provide a non-generic threat list, including threat generation, and this usually kills the tools overall usability. Only the specialist can extensively cover entire domains like mobile, embedded systems, cloud, OT, automotive, medical, etc.

The [Microsoft Threat Modeling tool](https://www.microsoft.com/en-us/securityengineering/sdl/threatmodeling), and others, are plagued by the problem that no one contributes their template files back to the community. I’m not sure if there are more than 10 threat model templates currently available on the internet.. that’s sad.

Sharing threat model templates, and getting the community to contribute, is by far the biggest challenge of templates. Industry and domain experts should be the ones creating, investing in, and sharing these templates.

But who should model? Everyone!

## Threat Modeling Manifesto

Which brings us to the [Threat Modeling Manifesto](https://www.threatmodelingmanifesto.org/). 

Referencing the manifesto, templates first help assist with: **“What are we working on?”.** Not in terms of decomposing any single application, but in terms of describing a consistent set of system components, architecture, and environmental aspects. 

Templates also address **“What could go wrong?”,** by using a threat list, threat logic, and threat generation to identify.

## Simplicity

***“Everything should be made as simple as possible, but no simpler”*** - Einstein quote that applies to modeling

Lastly, I also believe templates address an essential Threat Modeling Manifesto anti-pattern which is the Hero Threat modeler.

Given the speed of the security industry, the rapid change of the threat landscape, combined with the segregated and yet highly specialized knowledge required to continually identify “what could go wrong”, it’s becoming not practical for the threat modeler to traverse domains.

***“A jack of all trades is a master of none.”***

I see many teachers of Threat Modeling essentially imply that the hero threat modeler mentality is required to get the job done. That intimate knowledge of the entire threat landscape is needed. I mean who can blame them? They have a consultant business to sell and that’s what works for them. Getting value out of the process without a specialist can be impossible.

***“A jack of all trades is a master of none, but oftentimes better than a master of one.”*** - The original saying. Which still applies here because on the other side, too many modelers that aren’t specialists and therefore are not accounting for relevant threats that fall outside their domain. Incorporating templates into threat modeling can potentially account for what the modeler didn’t account for and fill gaps for the unknown knowns.

***“… that wasn’t in our threat model”***

With templates, the specialists does some work upfront so that the modeler can do less. Also while enabling the modeler to be more versatile and adapt to their threat landscape. Rather than the modeler solely using their acquired knowledge, they can also be a generalist from a predefined set of templates.

## Cons of Templates

The downside of producing a template is simply maintaining that template over time. As the threat landscape changes, a template could require capturing additional threats, additional diagram elements that begin appearing in new designs, or maybe just to modify an element property to contain more context about that element.

A downside of using template based models is being too reliant on the template’s threat list and threat logic. The threat list could be not as complete as the modeler thought. The threat logic could be flawed or have edge cases not addressed by the template designers. False positives can be identified as such within the generated threat list, but false negatives can be potentially disastrous.

## Future Of Template Diagraming

I believe the future process of Threat Modeling with templates to rely upon:

1. Combining templates as needed
1. Templates that include essential and actionable information in the form of threat or element properties
1. More domain specific templates owned by specialists
1. Searching repositories of community provided templates and importing individual elements or threats

To further describe #1, let's say you have a system with an IoT Bluetooth device that communicates to a mobile phone app and also has a cloud backend. Well, even if the backend was AWS, the previously mentioned AWS template wouldn’t be enough here. You’d want to combine the cloud template with other templates that have context for mobile and IoT applications. 

For #2, this is still far off, and we need templates to catch on first. But, so far I have [created a tool](https://github.com/tmart234/TMTool) that is an experiment that aims to assist in deriving risk scoring metrics by extracting threat or element properties from a model file. The idea seems promising in semi-automating some metrics. And I still think it could be helpful when scoring a large amount of vulnerabilities. But it undoubtedly needs some fine tuning.

Besides determining risk scoring metrics, templates can hold the foundation for compliance standards such as CAPEC, CWE, and ATT&CK. [pytm](https://github.com/izar/pytm/blob/master/pytm/threatlib/threats.json) has a good threat library that experiments with this although as previously stated I don’t agree with threat model tooling providing templates or part of a template.

For #3, we need specialists sharing their templates for modelers to traverse domains with ease. Templates should be owned by companies, working groups, and community projects and open sourcing should be encouraged to get feedback from other specialists.

And last, for #4, we first need to solve #3, then organize those templates into searchable repositories or libraries that tooling can use. And possibly a standard format and syntax to increase interoperability.

## Conclusion

Design and contribute templates. Use old models as a basis for doing so.


Here are some links if you want to explore Threat Model Templates:

- <https://github.com/matthiasrohr/OTMT/blob/master/secodis%20web%20plain.tb7>
- <https://github.com/rhurlbut/CodeMash2020/blob/master/CodeMash2020-Default.tb7>
- <https://github.com/microsoft/threat-modeling-templates>
- <https://github.com/nccgroup/The_Automotive_Threat_Modeling_Template>
- <https://threatsmanager.com/downloads/templates/>

