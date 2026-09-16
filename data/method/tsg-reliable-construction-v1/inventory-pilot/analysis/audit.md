# Independent audit of the original inventory pilot

The original three calls yielded **zero accepted inventories**. This is a delivery/interface pilot, not evidence of stable TSG quality. The frozen references and all original output files are unchanged.

| Case | Provider delivery | Original rejection | Source-grounded finding |
| --- | --- | --- | --- |
| Firmware | Complete JSON; `stop` | `r10: boundary must not broadcast into direct targets` | Failure guard is explicitly present, but runtime exception behavior is wrongly assigned `implementation` scope. Saved path is correctly the containment target; upload directory is a reference. |
| Pandoc | `length`; empty final answer | Completion did not finish with `stop` | All 16,384 completion tokens are reported as reasoning tokens. No final inventory exists; no API/guard accuracy can be inferred. |
| Book | Complete JSON; `stop` | `r1: boundary must not broadcast into direct targets` | Generation/interface content is correct, but `implementation` plus direct target is forbidden by the frozen interface. Exists, otherwise and failure guards are present and correctly bound. |

Firmware additionally contains **14 coverage links across 10 example units** whose cited requirement records do not cite those units. This is a duplicated citation-map inconsistency, not 14 independent semantic mistakes. Its first boundary failure prevents the original validator from reaching these later checks. Book has no such coverage/citation mismatch.

Book structurally records the alphanumeric-ID statement as an **assumption**, yet its free uncertainty notes question that same choice. The structured modality is correct against the frozen reference; the notes are inconsistent, not grounds to rewrite the reference. Its speculation about tuple quote style is not a source-imposed requirement.

The raw firmware input properties, byte type alternative, 256KB threshold, FWR1 header and saved-path confinement are present. The return requirement targets the returned message, so the missing explicit success guard is **not** scored as an error: the frozen reference permits normal-return scope in the target. Interface and storage are jointly represented rather than independently bound. Entity descriptions often contain the very policies attached as requirements; downstream interpretation must avoid making those policies inseparable from object identity.

The evidence supports interface fixes before integration: avoid independently regenerating citation coverage; make forbidden scope/target combinations explicit; distinguish runtime behavior from generation instructions; and leave sufficient output budget after reasoning. Clearing invalid targets alone would leave firmware's real scope error. The request also includes system text but supplies only user-unit citation IDs; program-owned fixed system facts need an explicit exemption, rather than treating their absence here as new source omission.

The detailed [review](review.json) maps all 24 frozen reference requirements for these three tasks to exact output records or nondelivery, preserves provider usage, input hashes and original failure messages, and separates raw semantic observations from accepted artifacts. No output has been repaired, no new provider call made, and no candidate/edit result claimed.
