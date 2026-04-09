---
layout: post
title: "The Security Mindset: A Field Guide for Junior Engineers"
mermaid: true
---

I keep finding myself repeating the same advice to junior engineers. None of it is about tools. None of it is about certifications. All of it is about how you think.

The gap between a junior and a senior security engineer isn't knowledge of CVEs or proficiency with a particular scanner. It's mindset. Mindset is the multiplier for everything else. And in medical device security, where patient safety is on the line, that multiplier matters even more. You can teach someone to run a tool in an afternoon. Teaching them to think like a security engineer takes years of deliberate practice.

This post is my attempt to distill the advice I find myself giving over and over. If you're early in your security career and wondering what separates the people who plateau from the people who keep leveling up, read on.

## How to Think

**Have a divergent mindset.** Professional hackers have a mantra: "try harder." But what that really translates to is "enumerate more solutions, assumptions, or information." It means go back to the drawing board. Be willing to ditch a solution quickly and never be personally or emotionally tied to it, because emotional attachment is a feature of a convergent mindset, not a divergent one.

In medical device security, this matters because the attack surface of a connected device is wider than most people assume. Bluetooth, Wi-Fi, USB, cloud APIs, clinical network integrations, firmware update mechanisms, even electromagnetic interference on analog sensors. Early research into implantable device security succeeded precisely because researchers enumerated attack vectors that nobody had considered for medical implants. The lesson: your first instinct about where the risk lives is probably incomplete. Enumerate further.

**Have a persistent mindset.** You might have already tried 24 times, but there's a good chance the 25th time works. It's almost always the last enumeration that is successful in a hack. And a lot of the time, that last enumeration effort is the hardest. Hackers are borderline obsessive in their level of persistence. Don't confuse "this is hard" with "this is impossible." The difference between the two is usually just one more attempt.

**Be skeptical.** Verify, never trust. Cybersecurity is notoriously over-promised and under-delivered by vendors, developers, and management alike. Truth is never black and white, and finding the real truth requires effort. Everything, even the machines, will lie to you.

In our industry, don't trust that a manufacturer has hardened a device just because they claim regulatory compliance. Do the basics: check host and network hardening, verify patching, confirm privilege reduction, validate MFA. These fundamentals haven't changed in 20+ years, and they remain the most common gaps. Compliance does not equal security. Verify everything.

**Be confidently curious.** Dive headfirst and always tinker with ideas. Ask plenty of questions. But also try to thoughtfully decipher next steps to further an idea before being directly told. This helps build initiative in finding and taking those steps without being asked, which is essential for later in your career.

You may approach a problem differently than your peers. Good. They should know about it. The curious engineer learns what's next and sets the tone for the rest of the team. Curiosity without confidence produces passive observers. Confidence without curiosity produces dangerous operators. You need both.

## How to Learn

**Be a good skim reader and searcher.** Good security engineers are extremely good at skimming and searching sources to find the important stuff. Documentation, RFCs, advisories, regulatory guidance, vendor specs. Learn to distill the noise. Enumerate all sources and types of documentation. You're the Sherlock Holmes of cybersecurity.

In medical device security, you'll be reading FDA pre-market and post-market cybersecurity guidance, IEC 62443, AAMI TIR57, SBOM specifications, and a dozen other standards. Nobody reads all of them cover to cover. Knowing how to scan a table of contents, search within a document, and recognize what's relevant versus noise is a genuine survival skill. Your Google-fu is a professional competency. Refine it deliberately.

**Adopt a classroom mentality.** Approach the first years of your security career as an educational experience with some work mixed in. Taking your own notes is typically the best way to learn a topic, and you'll encounter many new topics. It also shows good leadership to have notes after an important meeting. Take notes like you would in the classroom if you expect success, because the devil is in the details.

Pentesters are known to take extremely detailed notes during engagements. Their notes fuel their divergent mindset for what to try next. Your notes should do the same.

The training gap in this industry is real. The level of security engineering training that companies provide is rarely sufficient for what engineers actually need. Your notes are how you close that gap for yourself. Build a personal knowledge base. Your future self will thank you.

**Understand the big picture.** Think in terms of systems. Try to step back and reflect on the current activity you're doing. Does it make sense to you in the grand scheme? Can you visualize it? Can you answer why you are doing that particular work?

Personally, I can't fully enjoy work if I don't understand it. And deep understanding requires seeing the big picture. Problem solving can be stimulating and gratifying when you understand at both a low level and a high level. Otherwise it's just overwhelming.

A medical device doesn't exist in isolation. It lives in an ecosystem: clinical workflows, hospital networks, patient data flows, supply chains, and regulatory requirements. Security applies across the entire product lifecycle, from concept through design, implementation, supply chain, manufacturing, postmarket maintenance, and eventually end of life. A vulnerability in isolation is trivia. A vulnerability in context is a risk. The junior who can explain *why* a finding matters to patient safety will advance faster than the one who can only explain *what* the finding is.

## How to Work with People

**Be humble in your quest.** No one is the smartest. There are NO dumb questions here. But we must find, understand, and verify the true answer based on empirical evidence. To make good judgments, it often takes fully understanding a technical concept to its core.

You WILL fail if you practice the divergent mindset. That's the whole point. How will you deal with many failures? Being humble about failing is a quick path to success. The question isn't whether you'll be wrong, it's whether you'll learn from it or hide from it.

**You need people skills.** Fixing bad cyber may seem like a technical problem, but it's typically cultural. The only thing you can do to force cultural change in an organization is by being proactive with the developers and system engineers. To get external teams involved, they need to be invested and own their cybersecurity responsibilities. To be invested, they first need to like working with you.

In medical device security, your stakeholders extend beyond traditional engineering. Clinical engineers, biomedical teams, regulatory affairs, quality assurance. All of them need to be your allies. Coordinated vulnerability disclosure between researchers and manufacturers is a cultural challenge, not just a technical one. Bridges get built by people who are pleasant to work with. Practice people skills, curate relationships, and sell the idea of increased security. You and your team's influence is key to selling other teams the idea that security matters.

**Be a security enabler.** It needs to be clear that security is not a blocker. Security is most effective when you are enabling it, not when you enforce it. You are not the cyber police. That style will never be effective.

You can't sprinkle security pixie dust on a product after it's been designed. Security must be designed in from the start, not bolted on. But that means working WITH design teams early, not policing them late. Developers and managers who are hesitant to involve security almost always see it as a blocker for their team, similar to how they see quality or regulatory. Prove them wrong by showing outcomes. Enable the business, and they'll want you in the room for the next project.

**Choose the hill you die on carefully.** It's worth it to put your foot down or draw a line in the sand every once in a while in the name of security. But you may be digging your own grave by coming off as unreasonable. Try to rarely do this in your career, because it creates division between teams quite easily.

If you find yourself "putting your foot down" consistently, that's likely a cultural or management problem, not a technical or people problem. Never take a lack of security out on people. Mend broken relationships as soon as possible. Save your political capital for the things that genuinely matter. Be the person who, when they do raise the alarm, everyone listens, because they know you don't cry wolf.

## The Cybersecurity Stack

This is the single most important framework I can leave you with. Internalize this ordering and live by it:

{% raw %}
<div class="mermaid">
block-beta
    columns 1
    block:tooling["🔧 5. Tooling"]:1
        t1["Scanners"] t2["SIEMs"] t3["Fuzzers"] t4["Pentest Suites"]
    end
    block:coding["💻 4. Coding / Math"]:1
        c1["Scripting"] c2["Crypto Fundamentals"] c3["Logic"] c4["Automation"]
    end
    block:tech["⚙️ 3. Technology"]:1
        te1["Networking"] te2["Operating Systems"] te3["Cloud"] te4["Embedded Systems"]
    end
    block:process["📋 2. Processes"]:1
        p1["Vuln Management"] p2["Incident Response"] p3["Secure SDLC"] p4["Disclosure"]
    end
    block:concepts["🧠 1. Concepts (Layer 0)"]:1
        co1["Risk"] co2["Threat Modeling"] co3["CIA Triad"] co4["Attack Surfaces"]
    end

    style concepts fill:#2d6a4f,color:#fff,stroke:#1b4332
    style process fill:#40916c,color:#fff,stroke:#2d6a4f
    style tech fill:#52b788,color:#fff,stroke:#40916c
    style coding fill:#74c69d,color:#000,stroke:#52b788
    style tooling fill:#95d5b2,color:#000,stroke:#74c69d
</div>
{% endraw %}

*Start at the bottom. The foundation is where your investment pays off most.*

1. **Concepts** (layer 0): risk, threat modeling, CIA triad, trust boundaries, attack surfaces
2. **Processes**: vulnerability management, incident response, secure development lifecycle, coordinated disclosure
3. **Technology**: networking, operating systems, cloud architecture, embedded systems
4. **Coding / Math**: scripting, cryptographic fundamentals, logic, automation
5. **Tooling** (last): scanners, SIEMs, fuzzers, static analysis, penetration testing suites

Concepts first. Processes second. Then the underlying technology. Then coding and math. Then tooling last.

You'll find that the ones who focus on tooling first often lack understanding of basic concepts. Emphasizing this stack shows competence and critical thinking. Tools change every year. Concepts and processes are durable. Invest accordingly.

The basics of hardening, patching, and privilege reduction haven't changed in 20+ years, yet people still chase the latest tool. In medical device security specifically: know your dependencies (SBOMs), understand threat modeling, and grasp the regulatory frameworks before you ever reach for a scanner.

## Further Reading

The "Processes" layer of the stack deserves special attention. Over 25 years ago, Bruce Schneier wrote what remains one of the best articulations of this idea. His thesis: **security is a process, not a product**. Products provide some protection, but the only way to effectively operate in an insecure world is to put processes in place that recognize the inherent insecurity in the products. Prevention, detection, and response are ongoing and never finished.

Quality engineering learned this same lesson. **Quality is a process, not a checkbox.** Post-market surveillance, secure SDLC, vulnerability management -- these are quality disciplines applied to security. The engineer who says "we ran the scan, we're done" has a product mindset. The one who asks "what did we learn from the last incident and how do we prevent the next one?" has a process mindset. But process alone isn't enough. You also need a **systems mindset** -- one that understands how components fit together, what the requirements actually are, and where trust boundaries live. Threat modeling, network segmentation, understanding how a device's cloud API interacts with a clinical network -- that's systems thinking. Process thinking keeps you improving. Systems thinking tells you *what* to improve. A vulnerability management program (process) is only as good as the asset inventory and architecture understanding (systems) behind it. You need both.

If you read one thing after this post, make it <a href="https://www.schneier.com/essays/archives/2000/04/the_process_of_secur.html">The Process of Security</a> by Bruce Schneier (April 2000). It's short, it's free, and it will reframe how you think about everything above.

None of the twelve points in this post require a certification, a degree, or expensive tooling. They require deliberate practice and self-awareness. In medical device security, a compromised device isn't a data breach. It's a patient safety event. That's why mindset matters most.

You're going to feel like an impostor. That's normal. The fact that you're reading posts like this means you're already headed in the right direction.
