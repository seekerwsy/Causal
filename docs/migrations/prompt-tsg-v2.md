# Prompt TSG 2.1 breaking migration

Prompt TSG 2.1 is a breaking migration. Every run created with Prompt TSG 2.0 or earlier must
regenerate Prompt TSG v2 and every downstream stage under the 2.1 contract. v1 artifacts are rejected.
They are not converted, upgraded in place, or accepted through a compatibility reader.
An old manifest is not automatically upgraded, even when its artifact paths still exist.

Every source prompt now requires a non-empty `task_id`. A record without it is invalid rather than
being assigned an inferred or default task identity.

The causal boundary is unchanged by migration: Prompt TSG contains pre-treatment prompt graph
factors. Its `shadow` is read-only audit data and never an authority for discovery, intervention,
confirmation, or an outcome. The independent Semgrep 1.168.0 plus Bandit 1.9.4 Oracle remains the
only source of the security outcome `Y`.

## What was removed

Delete all legacy Code TSG artifacts and manifests, including:

- `tsg/observed_code_tsg.jsonl` and `tsg/counterfactual_code_tsg.jsonl`;
- `.stages/extract-code-tsg*.json` and any stage snapshots or transaction files for that stage;
- automation or scripts that call the `extract-code-tsg` CLI command;
- the `tsg.code_extractor` configuration key and the `python_ast_v0` value.

The command, configuration field, extractor implementation, artifacts, and manifests no longer
exist. Do not rename these files or feed them to Prompt TSG v2: there is no conversion or hidden
Code TSG compatibility path.

## Version and fingerprint boundary

Prompt TSG publication and skip decisions are bound to one version fingerprint:

- schema version: `2.1`;
- extractor version: `2.0`;
- catalog SHA-256: a canonical digest of the finite catalog, including ontology version `1.0`,
  motif version `1.0`, and every catalog entry;
- stage contract SHA-256: a digest that binds the schema version, extractor version, and catalog
  SHA-256 together.

The `extract-prompt-tsg` manifest records the catalog SHA-256, and consumers require the expected
catalog digest while holding the committed artifact. A catalog, schema, or extractor version
change changes the stage fingerprint and invalidates skip state. Editing a manifest cannot make a
v1 or otherwise stale artifact consumable.

## Extractor backend policy

`tsg.prompt_extractor` is an exact backend selection with three accepted values:

- `llm_facts_v1`: the default; an LLM emits structured semantic facts and the shared deterministic
  builder creates the graph;
- `llm_direct_graph_v1`: an LLM emits a typed graph proposal that is canonicalized by the same
  validator and builder boundary;
- `deterministic_catalog_v1`: the finite deterministic catalog backend used explicitly by the
  offline demo in `configs/demo.yaml`.

There is no per-prompt fallback and no automatic backend substitution. A selected backend either
produces a valid proposal for every prompt or the stage fails without publication. In particular,
an invalid LLM proposal is not retried semantically and is never replaced by deterministic output.

The two extraction outputs are `tsg/prompt_extraction_proposals.jsonl` and
`tsg/prompt_tsg.jsonl`. The proposal artifact preserves proposal provenance: source `prompt_id`,
required `task_id`, prompt digest, exact backend, policy digest, catalog digest, and bounded raw
response audit data. The graph repeats the proposal identifier and run-locked extraction
coordinates. The canonical graph—not proposal fields or audit projections—is the feature
authority for consumers.

The LLM backends require a non-secret `tsg.llm` block. `provider`, `base_url`, and `model_id`
identify the endpoint and model; `api_key_env` names the environment variable that holds the
credential. For example, `api_key_env: OPENAI_API_KEY` stores only the environment-variable name
in configuration. Never put the credential itself in YAML, command arguments, artifacts, or
manifests.

M4A intentionally does not implement a gold corpus, fairness score, extractor benchmark, backend
ranking, backend winner, automatic selection, or fallback. Those comparison facilities were
deferred; selecting one of the three backends is always an explicit configuration decision.

## Migrate a run directory

Do not mix pre-2.1 and 2.1 files in one run directory. The safest migration is to archive the
complete old directory and create a fresh directory:

```powershell
Move-Item -LiteralPath runs/demo -Destination runs/demo-v1-archive
secaware run-all --config configs/demo.yaml --run-dir runs/demo-v2 --force
```

`run-all` requires the exact Oracle analyzers and runtime capabilities documented in the README.
If either analyzer is invalid, migration fails closed and publishes no Oracle result.

If policy requires reusing the same directory name, first archive the whole directory, verify the
archive, and recreate the original path as an empty directory. Partial cleanup is unsupported
because Prompt TSG, generation, Oracle, discovery, intervention, confirmation, and report
manifests all fingerprint upstream artifacts. At minimum, all of these v1 outputs and downstream
stages must be removed and regenerated:

1. All TSG artifacts, manifests, seals, snapshots, backups, and transaction files.
2. Observed generation and Oracle outputs.
3. All discovery and intervention outputs.
4. Counterfactual generation and Oracle outputs.
5. All confirmation, analysis, and report outputs.
6. Every removed Code TSG artifact and manifest listed above.

Never retain a downstream result from a v1 run, even if its filename and JSON shape appear
unchanged.

## Verify the migration

Verify the installed CLI and repository have no legacy command or dead configuration:

```powershell
secaware --help
rg -n "extract-code-tsg|code_extractor|python_ast_v0" src configs
```

The help output must omit `extract-code-tsg`; the `rg` command must exit with status 1 and no
matches.

Then verify the new run directory and every persisted Prompt TSG record:

```powershell
$run = "runs/demo-v2"
if (-not (Test-Path -LiteralPath "$run/tsg/prompt_tsg.jsonl")) { throw "Prompt TSG artifact is missing" }
if (-not (Test-Path -LiteralPath "$run/.stages/extract-prompt-tsg.json")) { throw "Prompt TSG manifest is missing" }
python -c "import json,pathlib; p=pathlib.Path('runs/demo-v2/tsg/prompt_tsg.jsonl'); rows=[json.loads(x) for x in p.read_text(encoding='utf-8').splitlines() if x]; assert rows and all(r['schema_version']=='2.1' and r['task_id'] for r in rows)"
python -c "import json,pathlib,re; from secaware.tsg.catalog import PROMPT_TSG_CATALOG_SHA256; p=pathlib.Path('runs/demo-v2/.stages/extract-prompt-tsg.json'); m=json.loads(p.read_text(encoding='utf-8')); digest=m.get('catalog_sha256'); assert isinstance(digest,str) and re.fullmatch(r'[0-9a-f]{64}',digest) and digest==PROMPT_TSG_CATALOG_SHA256"
python -c "import pathlib; p=pathlib.Path('runs/demo-v2'); assert not list((p/'tsg').glob('*code_tsg*')); assert not list((p/'.stages').glob('extract-code-tsg*'))"
```

Both guarded `Test-Path` checks and all Python assertions must succeed. Finally, confirm that the
observed and counterfactual Oracle artifacts and their committed manifests exist. Those
`OracleRecord` values, not Prompt TSG or `shadow`, are the only authoritative security labels.
