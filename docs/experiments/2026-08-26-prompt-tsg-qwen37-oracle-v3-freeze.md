# Prompt TSG Qwen3.7 / Oracle-v3 replication freeze

This study is a prospective cross-model replication, not a reinterpretation of the completed Qwen3.5 strict-TSG result. It retains all 19 tasks in the previously frozen census and removes none using prior security, functionality, or generation outcomes. The same tasks therefore have prior Qwen3.5 outcome exposure, but no Qwen3.7 Max code outcome exists when this document is frozen.

The generator is `qwen3.7-max-2026-05-20`. The four assigned arms remain Absent, Specific, Generic, and Placebo. The primary estimand remains paired semantic-task-clustered ITT for Specific minus Placebo on observed secure-code yield. Functionality, joint success, Oracle evaluability, and unknown identification bounds remain separate outcomes. Pilot scaling uses protocol integrity only and all pilot assignments remain in the final denominator.

The task file is `data/formal/prompt-tsg-strict-v3-replication-tasks.jsonl`, SHA-256 `d2c201d7ed7d9ca95356fb25da38db0e779ae39480ebd64130fbbab10d1fb4af`. It contains CWE-22 (7), CWE-502 (6), CWE-78 (1), and CWE-89 (5). Prompt TSGs and their bindings are unchanged from the prior strict census.

The Oracle changes are prospective for this run and versioned rather than applied to old measurements. The path profile newly certifies stopping containment guards based on `Path.resolve` with `relative_to`/`is_relative_to`, or resolved paths checked with `os.path.commonpath`. The fixed-command profile certifies a literal executable with structured argv and shell disabled. The nine-case frozen calibration is `data/oracle-calibration/prompt-tsg-v3-cases.json`. These changes were motivated by coverage limitations observed in the prior study, so this run supports a replication/coverage claim rather than replacing the earlier primary result.

The frozen configuration is `configs/formal/prompt-tsg-strict-19-qwen37-oracle-v3.json`, SHA-256 `ecac3fa310e07bbac5fce7a7009a6d916df5d3d86c1314fbea7aa70a5d91bc2f`. No arm-specific program has been generated under this configuration at freeze time.
