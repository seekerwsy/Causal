from __future__ import annotations

from secaware.intervention import Arm, freeze_intervention
from secaware.measurement import FunctionalLabel, Measurement, SecurityLabel, TerminalFailure
from secaware.representation import Candidate, Operation, Task
from secaware.workflow import FrozenStudy, arm_texts, freeze_study


def example_study(*, seed: int = 17) -> FrozenStudy:
    tasks = (
        Task("task.a", "cluster.1", "CWE-89", "Use a SQL query."),
        Task("task.b", "cluster.2", "CWE-78", "Run a command."),
    )
    candidates = tuple(
        Candidate(task.task_id, f"feature.{task.task_id}", Operation.ADD, "frozen rationale")
        for task in tasks
    )
    interventions = tuple(
        freeze_intervention(
            candidate,
            arm_texts(
                target=f"{candidate.task_id}: target",
                noop=f"{candidate.task_id}: noop",
                placebo=f"{candidate.task_id}: placebo",
                generic=f"{candidate.task_id}: generic",
            ),
        )
        for candidate in candidates
    )
    return freeze_study(
        tasks,
        candidates,
        interventions,
        models=("model.a",),
        slots=tuple(range(8)),
        seed=seed,
    )


def complete_measurements(
    study: FrozenStudy,
    *,
    security: dict[Arm, SecurityLabel] | None = None,
    functionality: dict[Arm, FunctionalLabel] | None = None,
    unknown_assignment_id: str | None = None,
    failed_assignment_id: str | None = None,
) -> tuple[tuple[Measurement, ...], tuple[TerminalFailure, ...]]:
    security = security or {
        Arm.TARGET: SecurityLabel.SECURE,
        Arm.NOOP: SecurityLabel.INSECURE,
        Arm.PLACEBO: SecurityLabel.INSECURE,
        Arm.GENERIC: SecurityLabel.INSECURE,
    }
    functionality = functionality or {arm: FunctionalLabel.PASS for arm in Arm}
    measurements: list[Measurement] = []
    failures: list[TerminalFailure] = []
    for assignment in study.randomization.assignments:
        if assignment.assignment_id == failed_assignment_id:
            failures.append(TerminalFailure(assignment.assignment_id, "provider"))
            continue
        label = security[assignment.arm]
        if assignment.assignment_id == unknown_assignment_id:
            label = SecurityLabel.UNKNOWN
        measurements.append(
            Measurement(
                assignment.assignment_id,
                label,
                functionality[assignment.arm],
            )
        )
    return tuple(measurements), tuple(failures)
