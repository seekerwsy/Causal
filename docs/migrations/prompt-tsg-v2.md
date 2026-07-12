# Prompt TSG v2 breaking migration

Prompt TSG v2 is a breaking migration. Every run created with Prompt TSG v1 must regenerate
Prompt TSG v2 and every downstream stage. v1 artifacts are rejected and are not converted,
upgraded in place, or accepted through a compatibility reader.

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

- schema version: `2.0`;
- extractor version: `1.0`;
- catalog SHA-256: a canonical digest of the finite catalog, including ontology version `1.0`,
  motif version `1.0`, and every catalog entry;
- stage contract SHA-256: a digest that binds the schema version, extractor version, and catalog
  SHA-256 together.

The `extract-prompt-tsg` manifest records the catalog SHA-256, and consumers require the expected
catalog digest while holding the committed artifact. A catalog, schema, or extractor version
change changes the stage fingerprint and invalidates skip state. Editing a manifest cannot make a
v1 or otherwise stale artifact consumable.

## Migrate a run directory

Do not mix v1 and v2 files in one run directory. The safest migration is to archive the complete
old directory and create a fresh directory:

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

1. Prompt TSG artifacts, manifests, seals, snapshots, backups, and transaction files.
2. Observed generation and Oracle outputs.
3. Discovery and intervention outputs.
4. Counterfactual generation and Oracle outputs.
5. Confirmation, analysis, and report outputs.
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
python -c "import json,pathlib; p=pathlib.Path('runs/demo-v2/tsg/prompt_tsg.jsonl'); rows=[json.loads(x) for x in p.read_text(encoding='utf-8').splitlines() if x]; assert rows and all(r['schema_version']=='2.0' for r in rows)"
python -c "import json,pathlib,re; from secaware.tsg.catalog import PROMPT_TSG_CATALOG_SHA256; p=pathlib.Path('runs/demo-v2/.stages/extract-prompt-tsg.json'); m=json.loads(p.read_text(encoding='utf-8')); digest=m.get('catalog_sha256'); assert isinstance(digest,str) and re.fullmatch(r'[0-9a-f]{64}',digest) and digest==PROMPT_TSG_CATALOG_SHA256"
python -c "import pathlib; p=pathlib.Path('runs/demo-v2'); assert not list((p/'tsg').glob('*code_tsg*')); assert not list((p/'.stages').glob('extract-code-tsg*'))"
```

Both guarded `Test-Path` checks and all Python assertions must succeed. Finally, confirm that the
observed and counterfactual Oracle artifacts and their committed manifests exist. Those
`OracleRecord` values, not Prompt TSG or `shadow`, are the only authoritative security labels.
