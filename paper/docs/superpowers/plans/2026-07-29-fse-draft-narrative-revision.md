# FSE Draft Narrative Revision Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transform the current SecAware FSE manuscript into a publication-shaped, evidence-safe pre-results draft with a clear three-stage method story, verified citations, a vector overview figure, reproducible tables, and visually checked ACM output.

**Architecture:** Keep the approved causal and RQ specifications as immutable inputs. Revise the manuscript in coherent passes: evidence ledger and bibliography, front-matter story, three method stages and figure, evaluation tables, related work and back matter, then contract/build/visual verification. Quantitative result slots remain `--`; no result backfill is part of this plan.

**Tech Stack:** ACM `acmart`, LaTeX/`latexmk`, BibTeX through `acmart`, TikZ vector graphics, Python `unittest` paper contract, Ripgrep terminology scans, Poppler `pdfinfo`/`pdftoppm`.

---

## Working Directories and Authority

Use these roots consistently:

- Repository root: `D:\MyCode\Causal`
- Paper workspace: `D:\MyCode\Causal\paper`
- Manuscript directory: `D:\MyCode\Causal\paper\fse2027`
- Build directory: `D:\MyCode\Causal\paper\fse2027\out`
- Visual-review directory: `D:\MyCode\Causal\paper\tmp\pdfs\revised-draft`

Read these sources before changing Methods, Evaluation, Results, Threats, or
Conclusion:

- `paper/AGENTS.md`
- `paper/docs/superpowers/specs/2026-07-29-fse-draft-narrative-revision-design.md`
- `docs/superpowers/specs/2026-07-13-prompt-only-fci-jci-randomized-confirmation-design.md`
- `docs/superpowers/specs/2026-07-22-paper-research-questions-design.md`
- `.agents/skills/secaware-fse-paper/references/causal-boundaries.md`

Do not stage or modify the unrelated repository-root `uv.lock`.

### Task 1: Establish the Baseline and Evidence Ledger

**Files:**

- Create: `paper/fse2027/revision-evidence-ledger.md`
- Modify: `paper/fse2027/README.md`
- Verify: `paper/fse2027/secaware-fse2027-draft.tex`

- [ ] **Step 1: Run the current paper contract**

Run from `D:\MyCode\Causal`:

```powershell
.venv\Scripts\python.exe -m unittest tests.paper.test_secaware_fse_paper_contract -v
```

Expected: four tests pass. Record the exact test count and elapsed time in the
execution log.

- [ ] **Step 2: Compile and characterize the baseline PDF**

Run from `D:\MyCode\Causal\paper\fse2027`:

```powershell
latexmk -pdf -interaction=nonstopmode -halt-on-error -outdir=out secaware-fse2027-draft.tex
pdfinfo out\secaware-fse2027-draft.pdf
New-Item -ItemType Directory -Force '..\tmp\pdfs\current-draft'
pdftoppm -png -r 120 out\secaware-fse2027-draft.pdf ..\tmp\pdfs\current-draft\page
```

Expected: compilation succeeds; the pre-revision document is nine pages. A
different page count is acceptable only if the existing source changed after
this plan was written; record that divergence before proceeding.

- [ ] **Step 3: Capture the known conflict scan**

Run from `D:\MyCode\Causal\paper`:

```powershell
rg -n -S "one-hot|fallback|four-arm|After assignment, re-extraction|design-stage|skeleton|placeholder outcomes|no quantitative findings" fse2027\secaware-fse2027-draft.tex
```

Expected before revision: hits include one-hot JCI encoding, deterministic
extractor fallback language, generic four-arm language, post-assignment
re-extraction timing, design-stage positioning, and result-table draft labels.

- [ ] **Step 4: Create the evidence ledger**

Create `paper/fse2027/revision-evidence-ledger.md` with this structure and these
initial rows:

```markdown
# SecAware FSE Revision Evidence Ledger

**Revision:** 2026-07-29 narrative revision
**Primary manuscript:** `paper/fse2027/secaware-fse2027-draft.tex`

| Claim or manuscript element | Highest authority | Artifact path and field | Status | Revision action |
| --- | --- | --- | --- | --- |
| Prompt TSG supplies prompt semantics and variables, not causal edges | Approved causal design Sections 2–5 | Specification text; no quantitative artifact | Approved design | State once in setup and once in the figure caption |
| Stable possible paths are discovered with causal-learn FCI and task-cluster bootstrap | Approved causal design Section 6 | Implementation status supported by causal-boundary reference; paper-run evidence unavailable | Implemented core; final run absent | Describe the method; retain result slots |
| Hypotheses are frozen before confirm variants, assignments, code, and outcomes | Approved causal design Sections 6.3 and 10 | FrozenHypothesisRecord contract; final manifest absent | Implemented contract; final run absent | Use as the discovery/confirmation boundary |
| Primary confirmation is task-clustered assigned-arm ITT | Approved causal design Section 11 and RQ design Section 6 | Final effect artifact absent | Approved estimand; final run absent | Preserve exact denominator and retain `--` results |
| JCI uses one categorical `C_arm` column | Approved causal design Section 12 | JCI table contract | Current prose conflicts | Remove one-hot language |
| Deterministic extraction is an explicit run-locked backend | Approved causal design Sections 3.2 and 14 | Extractor policy contract | Current prose conflicts | Remove fallback language |
| Four arms apply to Safety ADD and Safety REMOVE | Approved causal design Section 8 | ArmProtocol contract | Current prose overgeneralizes | Qualify abstract, contribution, and figure language |
| Valid terminal non-success differs from missing or corrupt producer evidence | Approved causal design Sections 4.2, 11.1, and 15 | Outcome contract; final result artifact absent | Current prose is ambiguous | State zero versus replay boundary exactly |
| External adapters, RQ2 runs, RQ4 study, and final paper run are incomplete | Approved RQ design Section 12 and causal-boundary reference | No frozen final manifest | Planned, not executed | Use future tense and keep result slots |
| RQ1–RQ4 quantitative findings | Frozen final run and table builders required | No qualifying artifact identified | Blocked by evidence | Keep every result cell as `--` |
```

- [ ] **Step 5: Update the README revision boundary**

Add these paragraphs under `Current Scope` in
`paper/fse2027/README.md`:

```markdown
The 2026-07-29 narrative revision organizes the method as Security-Aware
Prompt Representation, Stability-Guided Causal Discovery, and Causal Effect
Confirmation. Its evidence ledger is `revision-evidence-ledger.md`.

The manuscript may describe verified core capabilities in the present tense,
but external RQ1 adapters, paper RQ2 runs, the RQ4 study, and the frozen final
paper run remain future work. Every numerical result stays `--` until a frozen
manifest and table builder supply exact provenance.
```

- [ ] **Step 6: Verify and commit Task 1**

Run from `D:\MyCode\Causal`:

```powershell
rg -n -S "Prompt TSG|assigned-arm ITT|C_arm|Four arms|final paper run|--" paper\fse2027\revision-evidence-ledger.md paper\fse2027\README.md
git diff --check -- paper\fse2027\revision-evidence-ledger.md paper\fse2027\README.md
git add paper\fse2027\revision-evidence-ledger.md paper\fse2027\README.md
git commit -m "docs: record FSE revision evidence boundaries"
```

Expected: the scan finds every boundary; `git diff --check` is empty; the
commit contains only the ledger and README.

### Task 2: Build the Verified Bibliography and Citation Map

**Files:**

- Create: `paper/fse2027/references.bib`
- Modify: `paper/fse2027/revision-evidence-ledger.md`
- Verify: primary publisher pages listed below

- [ ] **Step 1: Verify causal-method sources**

Verify author, title, year, venue, pages, DOI when available, and URL against:

```text
https://www.microsoft.com/en-us/research/publication/causal-inference-in-the-presence-of-latent-variables-and-selection-bias/
https://www.jmlr.org/papers/v9/zhang08a.html
https://www.jmlr.org/papers/v21/17-123.html
https://www.jmlr.org/papers/v25/23-0970.html
```

These sources support FCI under latent variables, PAG/ancestral-graph
semantics, JCI, and the causal-learn implementation. They do not support a
claim that SecAware invented those methods.

- [ ] **Step 2: Verify explanation-method sources**

Verify the corresponding records against:

```text
https://proceedings.mlr.press/v70/sundararajan17a.html
https://proceedings.mlr.press/v80/kim18d.html
https://papers.nips.cc/paper/2017/hash/8a20a8621978632d76c43dfd28b67767-Abstract.html
https://aclanthology.org/2020.acl-main.408/
https://aclanthology.org/2024.cl-2.6/
```

These records support input attribution, concept-level interpretation,
rationale evaluation, and explanation-faithfulness framing. They are related
work, not frozen RQ1 baseline implementations.

- [ ] **Step 3: Verify secure-code sources**

Verify the corresponding records against:

```text
https://doi.org/10.1109/SP46214.2022.9833571
https://doi.org/10.1145/3576915.3623157
https://proceedings.mlr.press/v235/he24k.html
https://aclanthology.org/2024.emnlp-main.806/
https://aclanthology.org/2026.acl-long.907/
```

These records support the security risk of AI-generated code and model-side
secure-code-generation interventions. Do not copy their reported numbers into
SecAware result prose.

- [ ] **Step 4: Create the bibliography**

Create `paper/fse2027/references.bib` using the publisher-exported BibTeX. The
file must expose these stable keys:

```bibtex
@inproceedings{spirtes1995fci,
  author = {Peter Spirtes and Christopher Meek and Thomas S. Richardson},
  title = {Causal Inference in the Presence of Latent Variables and Selection Bias},
  booktitle = {Proceedings of the Eleventh Conference on Uncertainty in Artificial Intelligence},
  pages = {499--506},
  publisher = {Morgan Kaufmann},
  year = {1995},
  url = {https://www.microsoft.com/en-us/research/publication/causal-inference-in-the-presence-of-latent-variables-and-selection-bias/}
}

@article{zhang2008ancestral,
  author = {Jiji Zhang},
  title = {Causal Reasoning with Ancestral Graphs},
  journal = {Journal of Machine Learning Research},
  volume = {9},
  number = {47},
  pages = {1437--1474},
  year = {2008},
  url = {https://www.jmlr.org/papers/v9/zhang08a.html}
}

@article{mooij2020jci,
  author = {Joris M. Mooij and Sara Magliacane and Tom Claassen},
  title = {Joint Causal Inference from Multiple Contexts},
  journal = {Journal of Machine Learning Research},
  volume = {21},
  number = {99},
  pages = {1--108},
  year = {2020},
  url = {https://www.jmlr.org/papers/v21/17-123.html}
}

@article{zheng2024causallearn,
  author = {Yujia Zheng and Biwei Huang and Wei Chen and Joseph Ramsey and Mingming Gong and Ruichu Cai and Shohei Shimizu and Peter Spirtes and Kun Zhang},
  title = {Causal-learn: Causal Discovery in Python},
  journal = {Journal of Machine Learning Research},
  volume = {25},
  number = {60},
  pages = {1--8},
  year = {2024},
  url = {https://www.jmlr.org/papers/v25/23-0970.html}
}

@inproceedings{sundararajan2017integrated,
  author = {Mukund Sundararajan and Ankur Taly and Qiqi Yan},
  title = {Axiomatic Attribution for Deep Networks},
  booktitle = {Proceedings of the 34th International Conference on Machine Learning},
  series = {Proceedings of Machine Learning Research},
  volume = {70},
  pages = {3319--3328},
  year = {2017},
  url = {https://proceedings.mlr.press/v70/sundararajan17a.html}
}

@inproceedings{kim2018tcav,
  author = {Been Kim and Martin Wattenberg and Justin Gilmer and Carrie Cai and James Wexler and Fernanda Vi{\'e}gas and Rory Sayres},
  title = {Interpretability Beyond Feature Attribution: Quantitative Testing with Concept Activation Vectors},
  booktitle = {Proceedings of the 35th International Conference on Machine Learning},
  series = {Proceedings of Machine Learning Research},
  volume = {80},
  pages = {2668--2677},
  year = {2018},
  url = {https://proceedings.mlr.press/v80/kim18d.html}
}

@inproceedings{lundberg2017shap,
  author = {Scott M. Lundberg and Su-In Lee},
  title = {A Unified Approach to Interpreting Model Predictions},
  booktitle = {Advances in Neural Information Processing Systems},
  volume = {30},
  year = {2017},
  url = {https://papers.nips.cc/paper/2017/hash/8a20a8621978632d76c43dfd28b67767-Abstract.html}
}

@inproceedings{deyoung2020eraser,
  author = {Jay DeYoung and Sarthak Jain and Nazneen Fatema Rajani and Eric Lehman and Caiming Xiong and Richard Socher and Byron C. Wallace},
  title = {{ERASER}: A Benchmark to Evaluate Rationalized {NLP} Models},
  booktitle = {Proceedings of the 58th Annual Meeting of the Association for Computational Linguistics},
  pages = {4443--4458},
  year = {2020},
  doi = {10.18653/v1/2020.acl-main.408},
  url = {https://aclanthology.org/2020.acl-main.408/}
}

@article{lyu2024faithful,
  author = {Qing Lyu and Marianna Apidianaki and Chris Callison-Burch},
  title = {Towards Faithful Model Explanation in {NLP}: A Survey},
  journal = {Computational Linguistics},
  volume = {50},
  number = {2},
  pages = {657--723},
  year = {2024},
  doi = {10.1162/coli_a_00511},
  url = {https://aclanthology.org/2024.cl-2.6/}
}

@inproceedings{pearce2022copilot,
  author = {Hammond Pearce and Baleegh Ahmad and Benjamin Tan and Brendan Dolan-Gavitt and Ramesh Karri},
  title = {Asleep at the Keyboard? Assessing the Security of {GitHub Copilot}'s Code Contributions},
  booktitle = {2022 IEEE Symposium on Security and Privacy},
  pages = {754--768},
  year = {2022},
  doi = {10.1109/SP46214.2022.9833571},
  url = {https://doi.org/10.1109/SP46214.2022.9833571}
}

@inproceedings{perry2023assistants,
  author = {Neil Perry and Megha Srivastava and Deepak Kumar and Dan Boneh},
  title = {Do Users Write More Insecure Code with {AI} Assistants?},
  booktitle = {Proceedings of the 2023 ACM SIGSAC Conference on Computer and Communications Security},
  pages = {2785--2799},
  year = {2023},
  doi = {10.1145/3576915.3623157},
  url = {https://doi.org/10.1145/3576915.3623157}
}

@inproceedings{he2024safecoder,
  author = {Jingxuan He and Mark Vero and Gabriela Krasnopolska and Martin Vechev},
  title = {Instruction Tuning for Secure Code Generation},
  booktitle = {Proceedings of the 41st International Conference on Machine Learning},
  series = {Proceedings of Machine Learning Research},
  volume = {235},
  pages = {18043--18062},
  year = {2024},
  url = {https://proceedings.mlr.press/v235/he24k.html}
}

@inproceedings{zhang2024seccoder,
  author = {Boyu Zhang and Tianyu Du and Junkai Tong and Xuhong Zhang and Kingsum Chow and Sheng Cheng and Xun Wang and Jianwei Yin},
  title = {{SecCoder}: Towards Generalizable and Robust Secure Code Generation},
  booktitle = {Proceedings of the 2024 Conference on Empirical Methods in Natural Language Processing},
  pages = {14557--14571},
  year = {2024},
  doi = {10.18653/v1/2024.emnlp-main.806},
  url = {https://aclanthology.org/2024.emnlp-main.806/}
}
```

Add the verified ACL 2026 DeepGuard entry only if the Related Work paragraph
uses it; otherwise omit it to keep the bibliography focused.

- [ ] **Step 5: Add citation-purpose rows to the ledger**

Append:

```markdown
| FCI handles latent-variable and selection-bias settings through PAG output | Spirtes et al. 1995; Zhang 2008 | `references.bib`: `spirtes1995fci`, `zhang2008ancestral` | Verified literature | Cite in discovery background without claiming unique DAG recovery |
| JCI combines context variables with causal discovery under explicit assumptions | Mooij et al. 2020 | `references.bib`: `mooij2020jci` | Verified literature | Cite in secondary-analysis subsection |
| Attribution, concept, and rationale methods provide complementary explanation evidence | IG, SHAP, TCAV, ERASER | `references.bib` verified keys | Verified literature; baseline execution absent | Cite only as related work |
| AI-generated code can contain security weaknesses, motivating secure-and-functional evaluation | Pearce et al. 2022; Perry et al. 2023 | Verified DOI records | Verified literature | Use in Introduction motivation |
| Model-side secure-generation methods optimize or retrieve for secure outputs | SafeCoder; SecCoder | Verified publisher records | Verified literature; not SecAware baselines by default | Contrast with prompt-side hypothesis confirmation |
```

- [ ] **Step 6: Verify bibliography syntax and commit Task 2**

Run from `D:\MyCode\Causal`:

```powershell
rg -n "^@" paper\fse2027\references.bib
rg -n -S "spirtes1995fci|mooij2020jci|zheng2024causallearn|pearce2022copilot|perry2023assistants|he2024safecoder|zhang2024seccoder" paper\fse2027\references.bib
git diff --check -- paper\fse2027\references.bib paper\fse2027\revision-evidence-ledger.md
git add paper\fse2027\references.bib paper\fse2027\revision-evidence-ledger.md
git commit -m "docs: add verified FSE literature sources"
```

Expected: thirteen entries are present before any optional DeepGuard entry;
the stable keys resolve exactly; the commit contains the bibliography and
ledger only.

### Task 3: Rewrite the Front Matter, Introduction, and Motivating Example

**Files:**

- Modify: `paper/fse2027/secaware-fse2027-draft.tex:1-179`
- Verify: `paper/fse2027/references.bib`

- [ ] **Step 1: Add citation and result-slot plumbing**

In the preamble:

```latex
\usepackage{booktabs}
\usepackage{flafter}
\usepackage{multirow}
\usepackage{tikz}
\usepackage{xspace}
\usetikzlibrary{arrows.meta,fit,positioning}

\newcommand{\tool}{SecAware\xspace}
\newcommand{\prompttsg}{Prompt TSG\xspace}
\newcommand{\resultslot}{\textbf{[Frozen paper-run headline results]}}
```

Remove `placeins` and the old `\todo` macro. Add before `\end{document}`:

```latex
\bibliographystyle{ACM-Reference-Format}
\bibliography{references}
```

- [ ] **Step 2: Replace the abstract**

Use this six-move content:

```latex
\begin{abstract}
Natural-language prompts are part of the security boundary of LLM code
generation: they can specify the required behavior while leaving validation,
authorization, trust boundaries, or safe-API constraints implicit. Existing
attribution and perturbation methods can expose influential text, yet they do
not by themselves turn that evidence into a task-preserving prompt
intervention with a confirmatory effect estimate. We present \tool, a
three-stage framework that constructs a security-aware prompt representation,
discovers stable prompt-side hypotheses with structure-constrained FCI, and
tests frozen hypotheses through held-out prompt interventions. The discovery
stage combines graph-derived variables, typed background knowledge, and
task-cluster bootstrap stability while preserving PAG uncertainty. The
confirmation stage freezes family-specific prompt variants before blocked
random assignment and estimates task-clustered assigned-arm intent-to-treat
effects on secure-and-functional outcomes. A fixed-budget evidence funnel
connects native candidates, target mappings, valid protocols, randomized
hypotheses, and confirmed effects across methods. \resultslot
\end{abstract}
```

The final sentence is visibly non-quantitative and cannot be mistaken for a
completed result.

- [ ] **Step 3: Rewrite the Introduction**

The section must contain five paragraphs in this order:

1. security consequence and practical prompt omission;
2. limitation of attribution, concept, rationale, and perturbation evidence;
3. the representation-to-hypothesis-to-effect gap;
4. the SecAware three-stage response; and
5. contributions.

Use citations in the first two paragraphs:

```latex
Studies of AI-assisted code generation show that functional-looking outputs
can still contain security weaknesses and that developers may overestimate the
security of assisted solutions~\cite{pearce2022copilot,perry2023assistants}.
Feature attribution, concept-based interpretation, and rationale evaluation
offer complementary views of model behavior~\cite{sundararajan2017integrated,
kim2018tcav,lundberg2017shap,deyoung2020eraser}, but importance or plausibility
alone does not identify the effect of an editable prompt requirement.
```

Use this contribution structure:

```latex
\begin{itemize}
  \item \textbf{Security-aware prompt representation.} A typed, catalog-bound
  representation converts free-form requirements into scoped, editable
  security factors and relational motifs.
  \item \textbf{Stable causal hypothesis discovery.} Structure-derived
  constraints, FCI, and task-cluster stability analysis prioritize
  reproducible prompt-side hypotheses and freeze them before confirmation.
  \item \textbf{Causal effect confirmation.} Family-specific prompt
  interventions and held-out blocked randomization produce hypothesis-specific
  assigned-arm ITT evidence without conditioning on realized edit success.
  \item \textbf{End-to-end evidence accounting.} A fixed-budget funnel exposes
  whether candidate generation, target mapping, protocolization, randomization,
  or confirmation limits each method.
\end{itemize}
```

- [ ] **Step 4: Add the motivating example and problem formulation**

Replace `Problem Setup and Scope` with:

```latex
\section{Motivating Example and Problem Formulation}

\subsection{An Editable Prompt-Side Security Factor}
Consider a security-neutral request to implement
\texttt{read\_report(base\_dir, user\_path)} and return the requested UTF-8
report. The request fixes the task but leaves path confinement implicit. A
target-specific variant can require resolving and normalizing the path under
\texttt{base\_dir} and rejecting any resolution outside that directory. A
no-op variant preserves the original security semantics, a length-matched
placebo changes presentation only, and a generic-control variant requests
secure coding without naming path confinement. This illustrative example
defines an intervention question; it does not report a generated program or an
effect.

\subsection{Units, Outcomes, and Claim Scope}
```

Then preserve the generation unit, discover/confirm split, task cluster, and
secure-and-functional outcome with these corrections:

```latex
Every committed assignment receives the prespecified secure-and-functional
outcome. A valid terminal generation, parse, functional, or Oracle-unknown
non-success is retained under that outcome policy. A missing or corrupt
required producer is instead a contract failure that blocks publication and
requires deterministic replay of the same assignment manifest.
```

Restrict the variable groups to:

```latex
$W$ contains approved pre-treatment task metadata; $X$ contains direct and
relational Prompt TSG queries; $Y$ contains independently committed outcomes;
and the secondary JCI table adds one categorical arm-context variable $C$.
Model identity remains an analysis coordinate and provenance field.
```

- [ ] **Step 5: Verify front-matter claims**

Run:

```powershell
rg -n -S "Security-aware prompt representation|Stable causal hypothesis discovery|Causal effect confirmation|End-to-end evidence accounting" fse2027\secaware-fse2027-draft.tex
rg -n -S "design-stage|numerical results remain intentionally blank|generation metadata|one-hot" fse2027\secaware-fse2027-draft.tex
```

Expected: all four contribution labels are present; the stale scan returns no
hits.

- [ ] **Step 6: Compile and commit Task 3**

Run:

```powershell
latexmk -pdf -interaction=nonstopmode -halt-on-error -outdir=out secaware-fse2027-draft.tex
rg -n -S "undefined citations|undefined references|Citation.*undefined|Reference.*undefined" out\secaware-fse2027-draft.log
git -C D:\MyCode\Causal diff --check -- paper\fse2027\secaware-fse2027-draft.tex
git -C D:\MyCode\Causal add paper\fse2027\secaware-fse2027-draft.tex
git -C D:\MyCode\Causal commit -m "docs: rewrite FSE opening around prompt-side effects"
```

Expected: build succeeds; warning scan is empty; the commit changes only the
manuscript.

### Task 4: Build the Three-Stage Method and Vector Overview

**Files:**

- Create: `paper/fse2027/figures/secaware-overview.tex`
- Modify: `paper/fse2027/secaware-fse2027-draft.tex:180-390`
- Verify: `paper/fse2027/revision-evidence-ledger.md`

- [ ] **Step 1: Invoke the engineering figure workflow**

Use the `engineering-figure-agent` skill to validate the figure brief against
the paper context. The figure must remain an exact vector diagram; do not use
an image generator for text, equations, or quantitative content.

- [ ] **Step 2: Create the TikZ overview**

Create `paper/fse2027/figures/secaware-overview.tex`:

```latex
\begin{tikzpicture}[
  font=\sffamily\footnotesize,
  stage/.style={
    draw=black,
    rounded corners=2pt,
    align=center,
    minimum height=9mm,
    minimum width=34mm,
    fill=black!5
  },
  artifact/.style={
    draw=black!70,
    rounded corners=1.5pt,
    align=center,
    minimum height=7mm,
    minimum width=27mm,
    fill=white
  },
  flow/.style={-{Latex[length=2mm]}, semithick},
  boundary/.style={densely dashed, semithick}
]
  \node[stage] (repr) {\textbf{Security-Aware}\\Prompt Representation};
  \node[stage, right=8mm of repr] (discover)
    {\textbf{Stability-Guided}\\Causal Discovery};
  \node[stage, right=13mm of discover] (confirm)
    {\textbf{Causal Effect}\\Confirmation};

  \node[artifact, below=5mm of repr] (tsg)
    {Prompt TSG\\local variables};
  \node[artifact, below=5mm of discover] (hyp)
    {FCI + task bootstrap\\frozen hypotheses};
  \node[artifact, below=5mm of confirm] (itt)
    {typed variants + assignment\\Oracle outcomes + ITT};

  \draw[flow] (repr) -- (discover);
  \draw[flow] (discover) -- (confirm);
  \draw[flow] (repr) -- (tsg);
  \draw[flow] (discover) -- (hyp);
  \draw[flow] (confirm) -- (itt);
  \draw[flow] (tsg) -- (hyp);
  \draw[flow] (hyp) -- (itt);

  \draw[boundary]
    ([xshift=6mm,yshift=5mm]discover.north east)
    --
    ([xshift=6mm,yshift=-17mm]discover.south east)
    node[midway, rotate=90, fill=white, inner sep=1pt]
    {\scriptsize hypothesis freeze};

  \node[fit=(repr)(discover)(tsg)(hyp), draw=black!50,
    rounded corners=3pt, inner sep=3mm,
    label={[font=\scriptsize]above:discover split}] {};
  \node[fit=(confirm)(itt), draw=black!50,
    rounded corners=3pt, inner sep=3mm,
    label={[font=\scriptsize]above:held-out confirm split}] {};
\end{tikzpicture}
```

- [ ] **Step 3: Replace the overview figure**

Use:

```latex
\begin{figure}[t]
  \centering
  \resizebox{\linewidth}{!}{%
    \input{figures/secaware-overview}
  }
  \caption{\tool converts prompt semantics into stable, frozen hypotheses and
  evaluates their security effects on held-out tasks. Prompt TSG edges provide
  typed structure rather than causal conclusions; generated code enters only
  the independent Oracle and functional-evaluation path in the confirmation
  stage.}
  \Description{Three-stage SecAware workflow. The discover split contains
  security-aware prompt representation and stability-guided causal discovery.
  A hypothesis-freeze boundary separates it from causal effect confirmation on
  held-out tasks using typed prompt variants, block randomization,
  generated-code evaluation, and assigned-arm ITT estimation.}
  \label{fig:overview}
\end{figure}
```

- [ ] **Step 4: Write `Security-Aware Prompt Representation`**

Organize subsections as:

```latex
\section{Security-Aware Prompt Representation}
\subsection{Typed Prompt Semantics}
\subsection{Run-Locked Extraction}
\subsection{Local Causal Variables}
```

Required content:

- define Prompt TSG after the task-facing explanation;
- distinguish task, safety, and presentation families;
- state catalog closure, evidence spans, and canonicalization;
- describe `LLM_FACTS_V1`, `LLM_DIRECT_GRAPH_V1`, and
  `DETERMINISTIC_CATALOG_V1` as explicit run-locked choices;
- state that identical-byte transport retries are permitted while semantic
  retries and favorable candidate selection are forbidden; and
- define `W`, `X`, `Y`, and JCI-only `C` without generated-code variables.

- [ ] **Step 5: Write `Stability-Guided Causal Discovery`**

Organize subsections as:

```latex
\section{Stability-Guided Causal Discovery}
\subsection{TSG-Derived Constraints}
\subsection{FCI and Task-Cluster Stability}
\subsection{Hypothesis Freeze}
```

Use:

```latex
The minimum backend is the established causal-learn implementation of
FCI~\cite{spirtes1995fci,zheng2024causallearn}. Its PAG output preserves
endpoint uncertainty under latent-variable assumptions rather than selecting a
single convenient orientation~\cite{zhang2008ancestral}.
```

Preserve one seed per task in the reference draw, task-cluster resampling,
endpoint-aware possible paths, the fixed top-`K` budget, and freeze before all
confirm artifacts.

- [ ] **Step 6: Write `Causal Effect Confirmation`**

Organize subsections as:

```latex
\section{Causal Effect Confirmation}
\subsection{Typed Intervention Protocols}
\subsection{Variant Freeze and Block Randomization}
\subsection{Outcomes and Assigned-Arm ITT}
\subsection{Evidence Levels and Secondary Structural Analysis}
```

Required corrections:

- four arms only for Safety ADD/REMOVE;
- arm-specific `AllowedDelta`, security-neutrality, provenance, and complete
  block freeze before randomization;
- independent, arm-blind re-extraction during variant validation;
- treatment fidelity recorded but never used to filter ITT;
- secure-and-functional outcome boundary;
- hypothesis-specific target-minus-no-op primary contrast;
- task-cluster uncertainty and frozen multiplicity;
- one categorical `C_arm` for JCI; and
- JCI/RFCI cannot change frozen hypotheses or primary ITT.

Use:

```latex
JCI treats the finite randomized arm role as one categorical context variable
and evaluates structural changes under explicit assumptions
~\cite{mooij2020jci}. It is secondary to the assigned-arm ITT estimate.
```

- [ ] **Step 7: Run the method consistency scan**

Run:

```powershell
rg -n -S "\\section{Security-Aware Prompt Representation}|\\section{Stability-Guided Causal Discovery}|\\section{Causal Effect Confirmation}" fse2027\secaware-fse2027-draft.tex
rg -n -S "one-hot|reproducible fallback|After assignment, re-extraction|every intervention.*four-arm|model_id.*causal variable|semantic retries" fse2027\secaware-fse2027-draft.tex
```

Expected: three stage headings are found; stale scan is empty.

- [ ] **Step 8: Compile, inspect the figure page, and commit Task 4**

Run:

```powershell
latexmk -pdf -interaction=nonstopmode -halt-on-error -outdir=out secaware-fse2027-draft.tex
New-Item -ItemType Directory -Force '..\tmp\pdfs'
pdftoppm -f 2 -singlefile -png -r 180 out\secaware-fse2027-draft.pdf ..\tmp\pdfs\method-figure
git -C D:\MyCode\Causal diff --check -- paper\fse2027\secaware-fse2027-draft.tex paper\fse2027\figures\secaware-overview.tex
git -C D:\MyCode\Causal add paper\fse2027\secaware-fse2027-draft.tex paper\fse2027\figures\secaware-overview.tex
git -C D:\MyCode\Causal commit -m "docs: present SecAware as a three-stage method"
```

Open `paper\tmp\pdfs\method-figure.png` with the image viewer. Expected: text is
legible at page scale; the discover and confirm bands do not overlap; the
freeze boundary is visible; no figure element is clipped.

### Task 5: Rebuild the Evaluation Narrative and Tables

**Files:**

- Modify: `paper/fse2027/secaware-fse2027-draft.tex`
- Verify: `docs/superpowers/specs/2026-07-22-paper-research-questions-design.md`

- [ ] **Step 1: Add the shared evaluation protocol**

Start the section with:

```latex
\section{Evaluation Design and Results}

All computational methods receive the same discover and confirm task
manifests, model and seed policy, independent Oracle and functional contract,
candidate budget, family-valid intervention protocol, randomization, outcome
encoding, task-cluster uncertainty, and multiplicity policy. Native candidates,
mappings, directions, and ranks are frozen before confirm outcomes exist.
```

- [ ] **Step 2: Preserve the four approved RQ sentences**

Use exactly:

```latex
\textbf{RQ1. How effectively can different methods discover and confirm
security-relevant prompt-side mechanisms in LLM code generation?}

\textbf{RQ2. How do SecAware's structured representation and causal analysis
components contribute to mechanism discovery and confirmation?}

\textbf{RQ3. Which prompt-side defensive interventions effectively reduce
insecure code generation?}

\textbf{RQ4. How do security experts rate and rank the perceived quality and
usefulness of explanations produced by different methods?}
```

- [ ] **Step 3: Replace the RQ1 table and prose**

Keep the count funnel:

```latex
\[
K \rightarrow N_{\mathrm{native}} \rightarrow N_{\mathrm{mapped}}
\rightarrow N_{\mathrm{protocol}} \rightarrow N_{\mathrm{randomized}}
\rightarrow N_{\mathrm{confirmed}}.
\]
```

Use method-family labels rather than pretending exact adapters are frozen:

```latex
\begin{table}[t]
  \centering
  \small
  \caption{RQ1 fixed-budget discovery-to-confirmation funnel. Confirmed yield
  at $K$ is the primary method-level endpoint; conditional mapping and
  confirmation rates diagnose where candidates leave the pipeline.}
  \label{tab:rq1}
  \begin{tabular}{lrrrrrr}
    \toprule
    Method family & $K$ & Native & Mapped & Protocol & Rand. & Conf. \\
    \midrule
    \tool & -- & -- & -- & -- & -- & -- \\
    Prompt attribution & -- & -- & -- & -- & -- & -- \\
    Prompt concepts & -- & -- & -- & -- & -- & -- \\
    Prompt perturbation & -- & -- & -- & -- & -- & -- \\
    LLM-judge explanation & -- & -- & -- & -- & -- & -- \\
    \bottomrule
  \end{tabular}
\end{table}
```

State that exact implementations and mappings are bound by the frozen RQ1
manifest before the final run.

- [ ] **Step 4: Replace the RQ2 table and prose**

Preserve the exact two-by-two design:

```latex
\begin{table}[t]
  \centering
  \small
  \caption{RQ2 isolates the contribution of relational Prompt TSG queries and
  FCI-based selection under the same fixed budget and confirmation protocol.}
  \label{tab:rq2}
  \begin{tabular}{llllrr}
    \toprule
    Variant & Representation & Selection & $K$ & Rand. & Conf. \\
    \midrule
    Full & direct + relational & FCI & -- & -- & -- \\
    Reduced representation & direct only & FCI & -- & -- & -- \\
    Association selection & direct + relational & G-square & -- & -- & -- \\
    Double ablation & direct only & G-square & -- & -- & -- \\
    \bottomrule
  \end{tabular}
\end{table}
```

Explicitly prohibit pooled cross-hypothesis ATE interpretation.

- [ ] **Step 5: Replace the RQ3 result slots**

Remove named targets that are not supported by the frozen final manifest. Use:

```latex
\begin{table}[t]
  \centering
  \small
  \caption{RQ3 reports hypothesis-specific target-versus-no-op assigned-arm
  effects. ADD and REMOVE remain separate estimands; placebo and generic-arm
  contrasts assess specificity.}
  \label{tab:rq3}
  \begin{tabular}{lllrrl}
    \toprule
    Frozen target & Op. & Outcome & ITT RD & Interval & Evidence \\
    \midrule
    \multicolumn{6}{c}{\emph{Rows generated from the frozen TargetSpec
    manifest}} \\
    \bottomrule
  \end{tabular}
\end{table}
```

Preserve task improvement, harm, and tie rates only as descriptive
diagnostics.

- [ ] **Step 6: Replace the RQ4 result slots**

Use:

```latex
\begin{table}[t]
  \centering
  \small
  \caption{RQ4 reports ordinal expert ratings and adjusted overall-usefulness
  contrasts for methods in the frozen human-study manifest.}
  \label{tab:rq4}
  \begin{tabular}{lrrrrr}
    \toprule
    Method & Clarity & Evidence & Credibility & Actionability & Usefulness \\
    \midrule
    \multicolumn{6}{c}{\emph{Method rows bound by the frozen study manifest}} \\
    \bottomrule
  \end{tabular}
\end{table}
```

State overall usefulness as the only primary RQ4 outcome and limit the claim to
perceived utility.

- [ ] **Step 7: Remove forced float barriers and report-language labels**

Remove every `\FloatBarrier`, “skeleton,” “placeholder outcomes,” and “all
cells remain blank” phrase. Keep the `--` evidence-safe cells.

- [ ] **Step 8: Verify RQ and table contracts**

Run from `D:\MyCode\Causal`:

```powershell
.venv\Scripts\python.exe -m unittest tests.paper.test_secaware_fse_paper_contract -v
rg -n -S 'confirmed yield at \$K\$|Rows generated from the frozen TargetSpec manifest|overall usefulness|pooled.*ATE' paper\fse2027\secaware-fse2027-draft.tex
rg -n -S "FloatBarrier|skeleton|placeholder outcomes|Input validation &|Safe API constraint &|Authorization guard &" paper\fse2027\secaware-fse2027-draft.tex
```

Expected: contract passes; required concepts are present; stale scan is empty.

- [ ] **Step 9: Compile and commit Task 5**

Run:

```powershell
latexmk -pdf -interaction=nonstopmode -halt-on-error -outdir=out secaware-fse2027-draft.tex
git -C D:\MyCode\Causal diff --check -- paper\fse2027\secaware-fse2027-draft.tex
git -C D:\MyCode\Causal add paper\fse2027\secaware-fse2027-draft.tex
git -C D:\MyCode\Causal commit -m "docs: align FSE evaluation with approved RQs"
```

Expected: build and contract pass; commit changes the manuscript only.

### Task 6: Add Related Work and Tighten the Back Matter

**Files:**

- Modify: `paper/fse2027/secaware-fse2027-draft.tex`
- Verify: `paper/fse2027/references.bib`

- [ ] **Step 1: Add `Related Work`**

Use three focused paragraphs:

```latex
\section{Related Work}

\paragraph{Prompt explanation and interpretation.}
Input attribution, concept-based interpretation, and rationale methods expose
features or evidence associated with model predictions
~\cite{sundararajan2017integrated,kim2018tcav,lundberg2017shap,
deyoung2020eraser}. Faithfulness remains distinct from explanation
plausibility~\cite{lyu2024faithful}. SecAware uses these methods as
complementary discovery families: its distinct objective is to map a native
candidate to an editable prompt-side factor, freeze that hypothesis, and
evaluate a prespecified intervention.

\paragraph{Security of LLM-generated code.}
Empirical studies have documented security weaknesses in generated code and
in AI-assisted programming outcomes
~\cite{pearce2022copilot,perry2023assistants}. Model-side methods such as
SafeCoder and SecCoder modify training or inference to improve secure code
generation~\cite{he2024safecoder,zhang2024seccoder}. SecAware instead asks
which prompt-side requirements have supported effects for a locked generator
and evaluation pipeline.

\paragraph{Causal discovery and heterogeneous contexts.}
FCI represents observational information under latent-variable uncertainty as
a PAG~\cite{spirtes1995fci,zhang2008ancestral}; causal-learn provides the
Python implementation used by SecAware~\cite{zheng2024causallearn}. JCI
introduces explicit context variables for multi-context causal discovery
~\cite{mooij2020jci}. SecAware contributes their security-specific
operationalization with prompt-derived constraints, task-cluster stability,
pre-confirmation freeze, and held-out assigned-arm effects.
```

- [ ] **Step 2: Tighten `Threats to Validity`**

Retain construct, discovery, internal, multiplicity, external, and human-study
threats. Each paragraph must follow:

```text
source of uncertainty -> mitigation or recorded diagnostic -> exact claim boundary
```

Remove phrases that merely repeat that FCI is not a unique DAG or that the
paper has no results. Preserve substantive limits on Oracle coverage, sample
support, intervention fidelity, multiplicity, locked scope, and perceived
utility.

- [ ] **Step 3: Tighten `Reproducibility`**

State the reproducible artifact chain:

```latex
\section{Reproducibility}
The anonymous package will bind task splits, Prompt TSGs, local tables,
background knowledge, PAGs, bootstrap support, frozen hypotheses and mappings,
prompt variants, assignment blocks, generated-code digests, Oracle and
functional outcomes, effect artifacts, and every table to versioned schemas,
configurations, code revisions, and parent-content digests. Demo runs remain
outside the paper table pipeline.
```

- [ ] **Step 4: Rewrite `Conclusion` and preserve `Data Availability` order**

Conclusion content:

```latex
\section{Conclusion}
\tool connects security-aware prompt representation, stability-guided causal
discovery, and causal effect confirmation in one auditable workflow. It turns
free-form prompt explanations into frozen intervention hypotheses and
evaluates them with task-clustered assigned-arm evidence on held-out tasks.
The fixed-budget evaluation further reveals whether representation,
discovery, operationalization, or confirmation limits each method. This design
supports precise claims about editable prompt-side security factors while
preserving uncertainty, failures, and provenance.
```

Data Availability remains immediately after Conclusion and accurately states
that the final result dataset is not yet frozen. Do not claim a persistent
location before it exists.

- [ ] **Step 5: Remove the report-style status section**

Delete `\section{Implementation and Study Status}`. Ensure the abstract,
evaluation tense, evidence ledger, and README still distinguish implemented
core capability from unexecuted paper studies.

- [ ] **Step 6: Verify citations, ordering, and stale status prose**

Run:

```powershell
rg -n -S "\\section{Related Work}|\\section{Threats to Validity}|\\section{Reproducibility}|\\section{Conclusion}|\\section{Data Availability}" fse2027\secaware-fse2027-draft.tex
rg -n -S "Implementation and Study Status|Consequently, this draft contains no quantitative findings|design-stage manuscript" fse2027\secaware-fse2027-draft.tex
latexmk -pdf -interaction=nonstopmode -halt-on-error -outdir=out secaware-fse2027-draft.tex
rg -n -S "undefined citations|undefined references|Citation.*undefined|Reference.*undefined" out\secaware-fse2027-draft.log
```

Expected: sections occur in the approved order; stale scan is empty; LaTeX
warning scan is empty.

- [ ] **Step 7: Commit Task 6**

Run:

```powershell
git -C D:\MyCode\Causal diff --check -- paper\fse2027\secaware-fse2027-draft.tex
git -C D:\MyCode\Causal add paper\fse2027\secaware-fse2027-draft.tex
git -C D:\MyCode\Causal commit -m "docs: complete FSE narrative and related work"
```

Expected: commit changes the manuscript only.

### Task 7: Full Contract, Terminology, Build, and Visual Verification

**Files:**

- Verify: `paper/fse2027/secaware-fse2027-draft.tex`
- Verify: `paper/fse2027/references.bib`
- Verify: `paper/fse2027/figures/secaware-overview.tex`
- Verify: `paper/fse2027/out/secaware-fse2027-draft.pdf`
- Update if evidence status changed: `paper/fse2027/revision-evidence-ledger.md`

- [ ] **Step 1: Run the paper contract**

From `D:\MyCode\Causal`:

```powershell
.venv\Scripts\python.exe -m unittest tests.paper.test_secaware_fse_paper_contract -v
```

Expected: all tests pass.

- [ ] **Step 2: Run the locked-boundary scans**

From `D:\MyCode\Causal\paper`:

```powershell
rg -n -S "Code TSG|code-side causal|one-hot|reproducible fallback|primary per-protocol|ITT sensitivity|conditional flip success|paired counterfactual|strict-confirmed precision|Relaxed directional replication|the confirm pool is filtered" fse2027\secaware-fse2027-draft.tex
rg -n -S "target_changed|semantic compliance|non-target drift|assigned-arm|task-clustered|C_arm|secure-and-functional" fse2027\secaware-fse2027-draft.tex
```

Expected: forbidden scan is empty. Required scan finds diagnostic/denominator
separation, assigned-arm ITT, task clustering, categorical JCI context, and the
primary outcome.

- [ ] **Step 3: Build the latest PDF and inspect the log**

From `D:\MyCode\Causal\paper\fse2027`:

```powershell
latexmk -pdf -interaction=nonstopmode -halt-on-error -outdir=out secaware-fse2027-draft.tex
rg -n -S "undefined citations|undefined references|Citation.*undefined|Reference.*undefined|Overfull \\hbox|LaTeX Error" out\secaware-fse2027-draft.log
pdfinfo out\secaware-fse2027-draft.pdf
```

Expected: compilation succeeds; warning scan is empty; `pdfinfo` reports an
anonymous ACM review PDF. The page count is recorded but not optimized by
deleting required content.

- [ ] **Step 4: Render every page**

Resolve and verify the target first:

```powershell
New-Item -ItemType Directory -Force 'D:\MyCode\Causal\paper\tmp\pdfs\revised-draft'
Resolve-Path 'D:\MyCode\Causal\paper\tmp\pdfs\revised-draft'
pdftoppm -png -r 150 'D:\MyCode\Causal\paper\fse2027\out\secaware-fse2027-draft.pdf' 'D:\MyCode\Causal\paper\tmp\pdfs\revised-draft\page'
```

Expected resolved path:
`D:\MyCode\Causal\paper\tmp\pdfs\revised-draft`.

- [ ] **Step 5: Inspect every rendered page**

Open every `page-*.png` with the image viewer. Check:

- title, anonymous author block, abstract, and first-page hierarchy;
- figure text, freeze boundary, and grayscale legibility;
- section transitions and paragraph density;
- equation alignment;
- table width and rule alignment;
- bibliography line breaks and URLs;
- headers, footers, line numbers, and anonymity;
- absence of clipping, overlap, black squares, broken glyphs, and abnormal
  blank regions.

If any defect appears, edit the smallest relevant LaTeX or TikZ scope, rebuild,
rerender, and reinspect all affected pages.

- [ ] **Step 6: Reconcile the evidence ledger**

For every quantitative cell and status sentence, confirm either:

```text
frozen artifact path + field + builder + run identity
```

or:

```text
explicit `--` result cell / accurately planned study tense
```

Do not replace any `--` during this task.

- [ ] **Step 7: Remove only generated visual-review files**

First verify both resolved targets begin with
`D:\MyCode\Causal\paper\tmp\pdfs\`:

```powershell
Resolve-Path 'D:\MyCode\Causal\paper\tmp\pdfs\current-draft'
Resolve-Path 'D:\MyCode\Causal\paper\tmp\pdfs\revised-draft'
```

Then remove only:

```powershell
Remove-Item -LiteralPath 'D:\MyCode\Causal\paper\tmp\pdfs\current-draft' -Recurse -Force
Remove-Item -LiteralPath 'D:\MyCode\Causal\paper\tmp\pdfs\revised-draft' -Recurse -Force
Remove-Item -LiteralPath 'D:\MyCode\Causal\paper\tmp\pdfs\method-figure.png' -Force -ErrorAction SilentlyContinue
```

Do not remove the final PDF under `paper\fse2027\out`.

- [ ] **Step 8: Commit any final verification corrections**

If visual or contract verification changed tracked files:

```powershell
git -C D:\MyCode\Causal diff --check
git -C D:\MyCode\Causal add paper\fse2027\secaware-fse2027-draft.tex paper\fse2027\references.bib paper\fse2027\figures\secaware-overview.tex paper\fse2027\revision-evidence-ledger.md paper\fse2027\README.md
git -C D:\MyCode\Causal commit -m "docs: finalize verified FSE pre-results draft"
```

If no tracked correction was necessary, do not create an empty commit.

### Task 8: Final Review and Handoff

**Files:**

- Review: all tracked files changed by Tasks 1–7
- Preserve: `uv.lock` and unrelated user changes

- [ ] **Step 1: Inspect the final diff**

Run from `D:\MyCode\Causal`:

```powershell
git status --short
git diff HEAD~6..HEAD --stat
git diff HEAD~6..HEAD -- paper\fse2027
```

Adjust the commit range if fewer or more task commits exist. Confirm that no
unrelated file entered the revision.

- [ ] **Step 2: Run the completion verification once more**

Run:

```powershell
.venv\Scripts\python.exe -m unittest tests.paper.test_secaware_fse_paper_contract -v
```

From `paper\fse2027`:

```powershell
latexmk -pdf -interaction=nonstopmode -halt-on-error -outdir=out secaware-fse2027-draft.tex
```

Expected: contract and build pass from the final tracked state.

- [ ] **Step 3: Prepare the handoff report**

Report:

- changed files and their responsibilities;
- final contract-test output;
- final LaTeX build result and page count;
- completed visual checks;
- retained `--` result fields by RQ;
- claims blocked by absent frozen evidence;
- the exact final PDF path; and
- the commit IDs produced by this plan.

Do not claim that final experiments, baselines, the human study, or numerical
paper findings are complete.
