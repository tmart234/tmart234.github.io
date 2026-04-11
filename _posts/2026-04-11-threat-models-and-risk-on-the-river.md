---
layout: post
title: "Threat Models and Whitewater River Paddling"
---

Threat models and risk assessments are universal. If you have the mentality, you can consistently apply it in all aspects of life. I spend a lot of time thinking about medical device security, but I also spend a lot of time on rivers doing whitewater rafting and kayaking. The crossover between the two is striking.

Here's how the same risk thinking shows up in both domains.

## 1. Environmental Risks 🌊

Neither domain can avoid or abstain from risk entirely. Whitewater paddlers accept certain dangers the moment they get on the river, just as medical device security teams accept risk by going to market. In some cases you cannot disconnect devices from a network, avoid using third-party software, or keep your system out of an operating room. The environment is the environment. You don't get to opt out of the parts you don't like.

Paddlers don't get to remove the rocks from the river. Security teams don't get to remove the device from the hospital. Both must prepare to engage with the inherent risks of where they operate, not pretend those risks don't exist or wish them away. Risk acceptance isn't negligence -- it's the prerequisite for doing the work at all.

## 2. A Solid Plan and Threat Model is 🔑

When preparing for difficult whitewater, paddlers study river features before ever getting to the river (put-in). This comes from a collection of known information -- what paddlers call "beta." Beta is the aggregate knowledge from guidebooks, trip reports, gauge readings, and the guy at the gas station who's lived on that river for forty years. Beta creates the initial mental threat model you use to avoid danger.

After studying beta, you mitigate by planning according to least risky options. That might look something like "go river left at the first rapid to avoid the center rock ledge" or "portage the horizon line if the gauge is above 3.5 feet." You haven't seen the river yet. But you've built an initial model based on the best available information, and that model drives your first set of decisions.

This is exactly what happens in a premarket threat model. You study the architecture, the deployment environment, the known weakness patterns (your CWEs), the known attack patterns (your CAPECs). You build a model. You plan mitigations based on least risky options. You haven't been attacked yet. But you've built something to reason against.

## 3. Update Your Threat Model 🧠

At the river, the paddler will scout rapids. Scouting is the act of stopping, getting out of the boat, and inspecting rapids or other hazards from a safe location -- usually from shore or an elevated rock. You compare what you're seeing to the beta you studied. Sometimes the beta was right. Sometimes the water level changed everything. Sometimes the beta was ten years old and a flood rearranged half the riverbed.

Threat modeling is never a one-and-done activity. Initial assumptiins break. Each time new information appears -- a scouting view, a vulnerability disclosure, a change in deployment architecture, a new software dependency -- the paddler updates their mental threat model, reassesses the risk, and considers how they will mitigate it during the run. Maybe the line you planned doesn't work at this water level. Maybe the control you designed doesn't cover the threat you just identified. Either way, you adapt the model or you're running blind.

The teams that treat their threat model as a static document delivered once during design review are the teams that get surprised. The paddlers who only go off Beta/previous knowledge stand a higher potentil to incur risk (swim).

## 4. Real-Time Monitoring 👀

After the paddler has a plan and has scouted, they need to execute it. When executing, they are actively reading the water in real-time to look for more unforeseen hazards. These hazards might not have been visible during scouting -- a downed tree just below the surface, a recirculating hole that only appears at this flow, a strainer that formed since the last person ran it. You planned. You scouted. And you still need to keep your eyes open.

Similarly, security teams are continuously monitoring for emerging threats despite having a threat model and controls in place. Post-market surveillance, anomaly detection, vulnerability feeds, incident alerts -- all of this is real-time water reading. The threat model told you what to expect. Monitoring tells you what's actually happening. And those two things are never perfectly aligned, which is why monitoring isn't optional even when you've done everything else right.

## 5. "We're All Between Swims" 🏊

In paddling, this saying acknowledges that everyone eventually flips or falls out, leading to a swim. In hard whitewater, swims are extremely unpleasant -- you're getting thrashed by hydraulics, bouncing off rocks, trying to get a breath between waves. So it's not a question of if; it's when. You can't be perfect forever.

In cybersecurity, breaches or attacks happen despite your best efforts. The "everyone swims" mindset promotes preparedness and humility over a false sense of invulnerability. The paddler who says "I never swim" is either lying or hasn't pushed themselves yet. The security team that says "we won't get breached" is operating on hope, not risk management.

This mentality is healthy. It doesn't mean you stop trying to stay in the boat. It means you plan for what happens when you don't. It means you practice your roll, your wet exit, your self-rescue -- because the swim is coming eventually, and the only variable is how well you handle it.

## 6. Redundancy and Preparation 🛟

Paddlers carry rescue gear, backup items, and have practiced rescue in similar scenarios. A swimming paddler may need a throw rope to get pulled to shore. Your boat may need a pin kit to get unstuck from a rock. You carry a breakdown paddle, a first aid kit, a whistle, a knife. You carry all of this knowing that most of it stays in your boat most days -- and that the one day you need it, nothing else matters.

This is defense in depth. Cybersecurity uses multiple layers of controls and rehearsed incident response procedures for when primary defenses or threat models fail. Firewalls, segmentation, endpoint detection, logging, backup restoration, communication plans -- each layer exists because no single layer is sufficient.

But gear alone isn't enough. The paddler who carries a throw rope but has never practiced throwing one is carrying dead weight. The security team with an incident response plan that's never been tabletop-exercised is in the same position. Think through every scenario that could go wrong. Have the emergency plan. And better yet, know how to execute it because you've practiced.

Prepare for your threat model to fail.

SYOTR 🫳
