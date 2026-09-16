# Source audit of v2 DeepSeek inventories

All three calls returned complete JSON. **Only book passed structural validation, and none of the three is semantically clean against the unchanged frozen references.** No TSG compilation, candidate acceptance or prompt edit was executed.

| Case | Original envelope | Critical semantic finding |
| --- | --- | --- |
| Firmware | Rejected: exact quoted `blob_name` with surrounding backticks is absent from signature unit u6 | r10 has the failure condition in prose but `guards=[]`: runtime scope improved while the condition disappeared from structure. |
| Pandoc | Rejected: coverage u6 lists r1 although r1 only cites u7 | r7 merges conditional logging with the wider exception ban under one failure guard. r8 keeps two API bans in one atom. r16 wrongly retains the overridden user Markdown obligation. |
| Book | Accepted structurally | r5 explicitly retains its failure guard but classifies runtime exception handling as `implementation`; this is a semantic error that structural validation does not catch. |

Firmware contains **three invalid source quotes**, for blob_name/blob_bytes/upload_dir in the full signature; those words exist, but they are not individually enclosed in backticks there. Other citations identify the correct entities. This is a literal-evidence defect, not proof that the object names were misunderstood. Its four safety requirements otherwise preserve their direct objects and values in raw records; the returned-message object correctly carries normal-return scope. The named interface remains fused with storage semantics rather than independently bound.

Pandoc has **four coverage-to-citation inconsistencies** (u6/r1, u9/r7, u10/r14, u11/r14). Its missing-file condition is correct. The conversion-failure condition is also explicitly present, but attached to a compound atom containing a broader exception rule. The two prohibited API names are present as text; this is not a missing keyword problem. Their required independent or explicit logical structure is absent, so the fixed single-API candidates remain unavailable. The final note notices the JSON/Markdown conflict but leaves both as decisive obligations, contrary to effective system priority.

Book's exists/otherwise conditions correctly govern the return value. The generic alphanumeric book-ID premise is recorded as an `assumption` over the book-ID class; a quantified representation is not rejected merely because the reference describes the input rather than identical graph topology. Its runtime failure layer remains wrong. **The one green envelope therefore cannot count as a correct graph.**

System units are now explicitly present. Firmware marks the general implement/preserve system reminders opaque and unresolved because it cannot bind them to runtime targets; these generation-level instructions do not need runtime targets. This is unnecessary abstention, not successful coverage. Its JSON and no-fences requirements, and book's effective system requirements, are present correctly.

[Detailed review](review.json) maps every one of the 24 frozen user requirements, includes all additional generation requirements, quotes exact records, records original failure messages and usage, and separates envelope validity from semantic assessment. All source text matches the original cases exactly; no reference or output was changed. The pilot changed prompt, citation domain and thinking policy together, so it does not isolate a causal advantage of disabling thinking and establishes no stability result.
