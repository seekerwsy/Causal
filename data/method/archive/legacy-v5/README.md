# Legacy v5 Prompt-TSG evidence

These two exact bundles preserve unique provider request/response evidence that
previously existed only below `.codex-runtime`. They are immutable
`LEGACY_ONLY` evidence for exposure and historical-result verification.

They are excluded from the target `phase-context-policy-v3` qualification,
discovery, confirmation, and reviewer-default data path. No task unit in either
bundle may be reassigned to `QUAL_DEV`, `QUAL_ACCEPT`, `DISCOVERY`, or
`CONFIRMATION`.

Each directory retains its original schema-2 artifact `manifest.json`; use the
generic exact-byte bundle verifier to authenticate it. Git history is the
recovery boundary after these copies are committed. The ignored runtime copies
must not be removed until the archive commit is durable.
