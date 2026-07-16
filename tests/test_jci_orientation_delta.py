from __future__ import annotations

import pytest

from secaware.causal.jci import build_jci_background
from secaware.errors import SecAwareError
from secaware.pipeline.artifact import canonical_sha256
from secaware.schema.causal import EndpointMark, PAGEdgeRecord, PAGRecord, PAGRunKind

from test_jci_fci_analysis import _config, _jci_table_and_rows


def _pag(
    run_kind: PAGRunKind,
    edges: tuple[PAGEdgeRecord, ...],
) -> PAGRecord:
    table, _rows = _jci_table_and_rows()
    base, provenance = build_jci_background(table)
    knowledge = (
        base if run_kind is PAGRunKind.JCI_RAW else provenance.materialized_background_knowledge
    )
    config = _config()
    return PAGRecord.from_content(
        run_kind=run_kind,
        table_id=table.table_id,
        backend=config.backend,
        backend_version=config.backend_version,
        ci_test=config.ci_test,
        config_sha256=canonical_sha256(config.model_dump(mode="json")),
        background_knowledge_sha256=knowledge.knowledge_sha256,
        variable_ids=tuple(item.variable_id for item in table.variables),
        edges=edges,
    )


def _raw_pag() -> PAGRecord:
    return _pag(
        PAGRunKind.JCI_RAW,
        (
            PAGEdgeRecord(
                left="c.arm",
                right="x.safety.sql_parameterization",
                left_mark=EndpointMark.CIRCLE,
                right_mark=EndpointMark.CIRCLE,
            ),
            PAGEdgeRecord(
                left="x.safety.sql_parameterization",
                right="y.secure_functional",
                left_mark=EndpointMark.TAIL,
                right_mark=EndpointMark.ARROW,
            ),
        ),
    )


def _constrained_pag() -> PAGRecord:
    return _pag(
        PAGRunKind.JCI_CONSTRAINED,
        (
            PAGEdgeRecord(
                left="c.arm",
                right="x.safety.sql_parameterization",
                left_mark=EndpointMark.TAIL,
                right_mark=EndpointMark.ARROW,
            ),
            PAGEdgeRecord(
                left="c.arm",
                right="y.secure_functional",
                left_mark=EndpointMark.CIRCLE,
                right_mark=EndpointMark.ARROW,
            ),
        ),
    )


def test_orientation_delta_records_whole_assumption_set_and_union_of_edge_pairs() -> None:
    from secaware.causal.jci import compare_jci_pags

    table, _rows = _jci_table_and_rows()
    _base, knowledge = build_jci_background(table)

    delta = compare_jci_pags(_raw_pag(), _constrained_pag(), knowledge)

    assert delta.raw_pag_id == _raw_pag().pag_id
    assert delta.constrained_pag_id == _constrained_pag().pag_id
    assert delta.assumption_ids == knowledge.assumption_ids
    assert delta.assumption_set_sha256 == canonical_sha256(list(knowledge.assumption_ids))
    assert delta.per_assumption_attribution is False
    assert tuple((item.left, item.right, item.change_kind) for item in delta.changes) == (
        ("c.arm", "x.safety.sql_parameterization", "marks_changed"),
        ("c.arm", "y.secure_functional", "edge_added"),
        ("x.safety.sql_parameterization", "y.secure_functional", "edge_removed"),
    )
    changed = delta.changes[0]
    assert (changed.raw_left_mark, changed.raw_right_mark) == (
        EndpointMark.CIRCLE,
        EndpointMark.CIRCLE,
    )
    assert (changed.constrained_left_mark, changed.constrained_right_mark) == (
        EndpointMark.TAIL,
        EndpointMark.ARROW,
    )
    assert delta.changes[1].raw_left_mark is None
    assert delta.changes[1].raw_right_mark is None
    assert delta.changes[2].constrained_left_mark is None
    assert delta.changes[2].constrained_right_mark is None


def test_no_change_delta_is_content_addressed_and_empty() -> None:
    from secaware.causal.jci import compare_jci_pags

    table, _rows = _jci_table_and_rows()
    _base, knowledge = build_jci_background(table)
    common_edges = (
        PAGEdgeRecord(
            left="c.arm",
            right="x.safety.sql_parameterization",
            left_mark=EndpointMark.TAIL,
            right_mark=EndpointMark.ARROW,
        ),
        PAGEdgeRecord(
            left="x.safety.sql_parameterization",
            right="y.secure_functional",
            left_mark=EndpointMark.TAIL,
            right_mark=EndpointMark.ARROW,
        ),
    )
    raw = _pag(PAGRunKind.JCI_RAW, common_edges)
    constrained = _pag(PAGRunKind.JCI_CONSTRAINED, raw.edges)

    first = compare_jci_pags(raw, constrained, knowledge)
    second = compare_jci_pags(raw, constrained, knowledge)

    assert first == second
    assert first.changes == ()
    assert first.delta_id.startswith("jci_delta_")


def test_endpoint_change_canonicalizes_endpoint_order_and_swaps_all_marks() -> None:
    from secaware.schema.outcomes import EndpointChangeRecord

    change = EndpointChangeRecord(
        left="y.secure_functional",
        right="c.arm",
        raw_left_mark=EndpointMark.ARROW,
        raw_right_mark=EndpointMark.CIRCLE,
        constrained_left_mark=EndpointMark.CIRCLE,
        constrained_right_mark=EndpointMark.TAIL,
        change_kind="marks_changed",
    )

    assert (change.left, change.right) == ("c.arm", "y.secure_functional")
    assert (change.raw_left_mark, change.raw_right_mark) == (
        EndpointMark.CIRCLE,
        EndpointMark.ARROW,
    )
    assert (change.constrained_left_mark, change.constrained_right_mark) == (
        EndpointMark.TAIL,
        EndpointMark.CIRCLE,
    )


@pytest.mark.parametrize(
    "payload",
    (
        {
            "raw_left_mark": EndpointMark.CIRCLE,
            "raw_right_mark": EndpointMark.CIRCLE,
            "constrained_left_mark": EndpointMark.TAIL,
            "constrained_right_mark": EndpointMark.ARROW,
            "change_kind": "edge_added",
        },
        {
            "raw_left_mark": None,
            "raw_right_mark": EndpointMark.CIRCLE,
            "constrained_left_mark": EndpointMark.TAIL,
            "constrained_right_mark": EndpointMark.ARROW,
            "change_kind": "edge_added",
        },
        {
            "raw_left_mark": EndpointMark.CIRCLE,
            "raw_right_mark": EndpointMark.CIRCLE,
            "constrained_left_mark": EndpointMark.CIRCLE,
            "constrained_right_mark": EndpointMark.CIRCLE,
            "change_kind": "marks_changed",
        },
    ),
)
def test_endpoint_change_rejects_incoherent_change_kinds(payload: dict[str, object]) -> None:
    from secaware.schema.outcomes import EndpointChangeRecord

    with pytest.raises(Exception, match="JCI"):
        EndpointChangeRecord(
            left="c.arm",
            right="x.safety.sql_parameterization",
            **payload,
        )


def test_delta_schema_rejects_forged_digest_id_and_duplicate_changes() -> None:
    from secaware.schema.outcomes import JCIOrientationDeltaRecord

    table, _rows = _jci_table_and_rows()
    _base, knowledge = build_jci_background(table)
    valid = __import__("secaware.causal.jci", fromlist=["compare_jci_pags"]).compare_jci_pags(
        _raw_pag(), _constrained_pag(), knowledge
    )

    for mutation in (
        {"assumption_set_sha256": "f" * 64},
        {"delta_id": "jci_delta_" + "f" * 64},
        {"changes": (valid.changes[0], valid.changes[0])},
        {"assumption_ids": (valid.assumption_ids[0], valid.assumption_ids[0])},
    ):
        forged = valid.model_construct(**{**valid.__dict__, **mutation})
        with pytest.raises(Exception, match="JCI"):
            JCIOrientationDeltaRecord.model_validate(forged)


def test_delta_factory_rejects_oversized_sequences_before_iteration() -> None:
    from secaware.schema.outcomes import JCIOrientationDeltaRecord

    touched = {"assumptions": False, "changes": False}

    class _OversizedAssumptions:
        def __len__(self) -> int:
            return 9

        def __getitem__(self, _index: int) -> str:
            touched["assumptions"] = True
            raise AssertionError("oversized assumptions must not be iterated")

    class _OversizedChanges:
        def __len__(self) -> int:
            return 64 * 63 // 2 + 1

        def __getitem__(self, _index: int) -> object:
            touched["changes"] = True
            raise AssertionError("oversized changes must not be iterated")

    for assumptions, changes in (
        (_OversizedAssumptions(), ()),
        (("jci.randomized_context_exogeneity.v1",), _OversizedChanges()),
    ):
        with pytest.raises(Exception, match="JCI"):
            JCIOrientationDeltaRecord.from_content(
                raw_pag_id=_raw_pag().pag_id,
                constrained_pag_id=_constrained_pag().pag_id,
                assumption_ids=assumptions,  # type: ignore[arg-type]
                changes=changes,  # type: ignore[arg-type]
            )
    assert touched == {"assumptions": False, "changes": False}


def test_delta_comparison_rejects_wrong_pag_or_assumption_provenance() -> None:
    from secaware.causal.jci import compare_jci_pags

    table, _rows = _jci_table_and_rows()
    base, knowledge = build_jci_background(table)
    raw = _raw_pag()
    forged_raw = PAGRecord.from_content(
        **{
            **raw.model_dump(
                mode="python",
                exclude={"pag_id", "background_knowledge_sha256", "edges"},
            ),
            "edges": raw.edges,
            "background_knowledge_sha256": knowledge.materialized_background_knowledge.knowledge_sha256,
        }
    )
    assert base.knowledge_sha256 != forged_raw.background_knowledge_sha256

    with pytest.raises(SecAwareError, match="JCI"):
        compare_jci_pags(forged_raw, _constrained_pag(), knowledge)
