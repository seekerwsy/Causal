# TSG reliability development: output limits, references and source construction

This is exposed-source development, not formal qualification or evidence of a code
security effect. The owner added CNY30; CNY4.903512 remained, giving a new ceiling
of CNY34.903512. No paper, protected task or Pair experiment was changed.

## Completed provider checks

Eleven calls cost a conservative CNY1.676793, leaving CNY33.226719 of authorization.
Failed/unverified calls retain their full reservation. These are accounting bounds,
not provider invoices. Every request, response, failure and cost replays offline.

| Check | Complete responses | Structural result | Source-semantic result |
| --- | --- | --- | --- |
| DeepSeek Flash thinking, three independent inventories | 2/3 | 0/3 accepted | Two scope errors; Pandoc used all 16,384 tokens for reasoning and delivered no content. |
| Corrected inventory interface, DeepSeek Flash without thinking | 3/3 | 1/3 accepted | 0/3 clean; omitted guard, merged requirements, wrong generation boundary and message priority. |
| Same corrected interface, Qwen Max with thinking | 3/3 | 2/3 accepted | 0/3 clean; conditions remained prose, branches/API bans merged, overridden Markdown instruction retained. |
| Compact candidate transport, separate binding references | 1/1 | Rejected | All four factor meanings pointed to incorrect bindings. |
| One decision per exact requirement reference | 1/1 | All 25 decisions compiled | All 12 factor definitions matched their source nodes; author review accepted two and rejected ten. |

Inventory inputs were firmware, Pandoc and book tasks already used in development.
The source reference was reviewed and fixed before the new outputs; it is an author
reference, not independent human gold. Conditions internal to the Pandoc exception
clause have a documented interpretation ambiguity; that dispute is reported apart
from unambiguous missing branches, combined API atoms and message-priority errors.
The initial inventory interface mistakenly lacked evidence units for system text
despite supplying the text. It also left some validator constraints implicit.
The corrected interface supplies all source segments and makes existing rules
explicit; earlier results retain their original failures. Because the interface
changed, the first two DeepSeek batches are not a clean thinking ablation.

## Why Flash was truncated

The previous Qwen Flash candidate call used an 8,192-token output cap and returned
`finish_reason=length`. It completed 17 factors but only six of 25 dispositions.
This was a completion limit, not lost connectivity. Repeated full identifiers and
binding descriptions enlarged the response, alongside inappropriate candidates.

The first compact call used 7,220 input and 2,838 output tokens and stopped normally,
but confused binding numbers with node numbers. The revised call used 7,028 input
and 2,250 output tokens. Input and output now share the exact requirement key; the
schema requires one decision per requirement. The program restores the original
complete scopes. The model cannot choose baskets of nodes or recreate bindings.
Prompt and representation changed together, so these are diagnostic observations,
not a controlled causal estimate of one formatting change.

Semantic selection remains fallible. The second compact response selected 12
requirements, including ordinary input interfaces/exception behavior, redundant
policy statements and a pre-existing wrongly bound path requirement. Author review
accepted only the firmware size limit and FWR1 header. The existing compiler froze
two reviewed factors/four ADD/REMOVE policies with zero additional calls. Fresh
catalogue-conditioned extraction and actual text edits have not run; these are not
two automatically qualified factors or successful interventions.

## Current method decision

The exact-reference candidate transport replaces the inefficient transport.
Semantic review remains necessary. Independent obligation inventory has **not**
been adopted as an extra default stage, a reliable reference or a replacement
for full TSG construction. Adding it without evidence would add cost and another
fallible representation. Default construction still uses source records, one
ordinary review, at most one local patch, and deterministic compilation.

A separate bounded construction-agent pilot uses fresh contexts with only original
source, the existing record schema and deterministic compiler feedback. It has no
reference answers or previous outputs, at most three attempts per task, and stops
at first compilation success. It uses Codex account usage, not external-provider
budget. Its model/runtime differ from the provider checks, so any improvement
cannot isolate an agent-workflow effect. The pilot's results and source audit live
under `agent-construction-pilot`. All three first attempts compiled without repair.
The post-output source audit checked all 24 fixed reference requirements, every
additional requirement and 17 operation/input/result roles. It found no confirmed
critical binding mismatch in these three graphs. A small passing pilot does not
establish stability on repeated or new natural tasks, and the absence of repairs
means compiler feedback cannot explain the observed difference from provider runs.

The graph-to-candidate mapping has a concrete separate limitation: valid firmware
size/header requirements directly constrain `blob_bytes`, but the current projector
requires an additional direct requirement-to-operation edge. These requirements
therefore have zero candidate bindings. That is not proof of extraction error.
Saved-path containment also has a valid direct object target without a represented
operation incidence. Adding a false producer or broader operation constraint solely
to satisfy the projector would change the source meaning. Object-bound policy
projection must be resolved before these graphs support the intended comparisons.

One debug label was also corrected prospectively: absence of an operation execution
gate now reads “NO DECLARED EXECUTION GUARD,” not “UNCONDITIONAL execution.” An
operation's presence does not mean it executes on every path. This changes no graph,
compiler rule or requirement guard; old archived readbacks remain unchanged. A
missing **requirement** condition is still a semantic omission, not excused by this
clarification.

## Reproduction and boundaries

Artifact root: `data/method/tsg-reliable-construction-v1`. Each provider experiment
contains frozen inputs, an exact source archive, credential-free wire traces,
result archive and source audit. Original archives protect old response formats.
Credentials remain owner-only on the existing server and are absent from packages.

```powershell
.venv/Scripts/python.exe data/method/tsg-reliable-construction-v1/verify.py
```

This replays all eleven retained calls without network access using their exact
archived implementations. It verifies request bytes, output/failure and conservative
cost, not natural-language correctness. It also recompiles the three retained agent
responses against their archived implementation; it does not resample the agents.
The affected full default suite passed
103 checks in the existing clean supported environment. These implementation checks
do not compensate for the observed semantic failures.
