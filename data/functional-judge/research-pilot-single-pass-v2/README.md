# Research-task functional Judge canary v2

V2 preserves the five-task, ten-case balance of v1 while making the authentication fixture's GUI
and navigation collaborators explicit function dependencies. It also uses the revised Judge
policy that forbids inventing robustness requirements absent from the frozen task contract.

- Source contracts: `data/functional-audit/pilot-v1/contracts.jsonl`
- Expected decisions: five `pass`, five `fail`
- CWE coverage: CWE-78, CWE-89, CWE-94, and CWE-502
- Primary Judge mode: one blind, schema-validated pass with seed 73001
- Excluded from causal and ITT estimates: yes

V1 inputs and its 8/10 immutable result are retained. V2 uses new case IDs and seeds so every
setting and result remains distinguishable.

## Recorded validation history

The immutable `bailian-qwen35flash-single-research-20260814-02` run accepted the first four cases.
On case five the model reached the expected `pass` decision but inserted `...` inside a purported
verbatim evidence excerpt. The strict evidence validator rejected it, so the remaining six cases
were not silently skipped. The policy was revised to prohibit omitted-text markers and to require
separate array items for discontinuous evidence. Because that changes the policy hash, the next
run repeats all ten cases under one policy instead of combining incomparable partial results.

Runs `-03` and `-04` showed that verbatim text copying remained unstable: the model respectively
removed indentation from a multi-line excerpt and reformatted a multi-line call as one line. These
were correctly rejected, but adding more text-copying rules was abandoned. The response contract
now asks for bounded integer source-line numbers; the local validator checks them and resolves
them to exact source text. The two-case line-number transport canary
`bailian-qwen35flash-single-lines-20260814-01` passed, followed by the complete immutable run
`bailian-qwen35flash-single-research-20260814-05`: 10/10 expected decisions, 10 pass records,
10 outcomes, 10 exchange traces, five tasks, one evaluator policy, and no persisted API key.
