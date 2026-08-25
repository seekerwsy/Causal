# Prompt TSG strict four-arm results (v2)

The prospective study completed 19 semantic task clusters and all 76 assigned arms on Qwen3.5 Flash. All assignments produced AST-valid, compiling Python; the independent verifier reproduced the arm counts, paired ITT contrasts, unknown bounds, and simultaneous intervals from the closed measurement ledger.

The primary result is null. Secure-code yield was 11/19 (57.9%) in each of Absent, Specific, Generic, and Placebo. Specific minus Placebo was therefore 0.0 percentage points, with no task-level secure improvement or harm. This is not evidence that the effects are exactly equal: Oracle unknowns give a primary identification range from -15.8 to +26.3 percentage points, and the registered test does not distinguish the contrast from zero.

Functionality was 17/19 (89.5%) in both Specific and Placebo, so the primary functionality difference was zero and met the frozen 10-point non-inferiority margin. Secure-and-functional joint yield was also 10/19 in both arms. Oracle evaluability was lower under Specific: 14/19 versus 16/19 under Placebo, a -10.5-point difference.

Feature-level diagnosis explains the observed zero:

- all six JSON/YAML deserialization tasks and all five SQL-value tasks were already labelled secure in every arm, leaving no observed improvement margin;
- none of the seven path-confinement tasks was labelled secure in any arm; one Specific output added an `abspath` containment guard and moved from insecure to unknown, because the local Oracle did not certify that pattern;
- the single fixed-executable task used `['bsub'] + args` in every arm; Specific made `shell=False` explicit, but the static trace classified list concatenation as an unresolved formatted command, moving Specific from insecure to unknown rather than secure;
- Specific therefore changed coverage on two tasks but never changed the observed secure indicator. Unknown outcomes remain unknown and are not promoted to secure.

The supported conclusion is: on this fresh strict-TSG population, a specific mechanism requirement did not demonstrate higher secure-code yield than an equally sized style placebo, while observed functionality was non-inferior. Prompt TSG improved the validity of task-to-mechanism binding, but better binding alone did not overcome baseline security ceilings or Oracle coverage limits.

This result must not be tuned into significance. A subsequent prospectively frozen study may expand fresh non-ceiling tasks and qualify the Security Oracle on common correct mechanism patterns such as fixed executable list concatenation, `Path.resolve`/`is_relative_to`, and `abspath`/`commonpath`. Such work is a new study; it cannot reinterpret this frozen primary result.
