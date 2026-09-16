"""One frozen candidate call through the existing compiler; retain exact wire and cost.

This is a development artifact, not an additional method path. Optional replay
replaces the HTTP transport and asserts exact request bytes.
"""
import json
import os
from pathlib import Path
import sys
from time import monotonic

from prompt_mechanism_study.artifact_io import read_json, write_bundle
from prompt_mechanism_study.candidate_construction import build_candidate_catalog
from prompt_mechanism_study import functional_judge


def run(base, output, retained=None):
    assert not output.exists()
    config = base / "proposal-config-canonical"
    plan = read_json(config / "plan.json")
    cap = plan["maximum_conservative_cost_microunits"]
    call = dict(trace={}, response_text=None, error=None)
    count = 0
    original = functional_judge.bailian_complete
    if retained is not None:
        saved = read_json(retained / "call/call.json")
        os.environ["ALI_BAILIAN_API_KEY"] = "offline-replay-only"

        def transport(request, *, timeout):
            assert request.data.decode() == saved["trace"]["request"]
            assert timeout == saved["evaluator"]["timeout_seconds"]

            class Response:
                def __enter__(self): return self
                def __exit__(self, *args): return False
                def read(self, maximum): return saved["trace"]["response"].encode()[:maximum]

            return Response()

        functional_judge.urlopen = transport

    def complete(request, evaluator, prompt):
        nonlocal count
        assert count < plan["maximum_provider_calls"] == 1
        assert evaluator["maximum_input_bytes"] * 6 + evaluator["maximum_output_tokens"] * 24 <= cap * 10
        count += 1
        call.update(request=request, evaluator=evaluator, system_prompt=prompt)
        started = monotonic()
        try:
            raw = original(request, evaluator, prompt,
                trace=lambda kind, value: call["trace"].update({kind: value.decode()}))
            call["response_text"] = raw.decode()
            return raw
        except Exception as error:
            call["error"] = dict(type=type(error).__name__, message=str(error))
            raise
        finally:
            charge = cap
            try:
                envelope = json.loads(call["trace"]["response"])
                pt, ct = (envelope["usage"][key] for key in ("prompt_tokens", "completion_tokens"))
                amount = (pt * 6 + ct * 24 + 9) // 10
                if (call["error"] is None and type(pt) is int and type(ct) is int
                    and 0 < pt <= evaluator["maximum_input_bytes"]
                    and 0 < ct <= evaluator["maximum_output_tokens"]
                    and envelope["model"] == evaluator["model_id"]
                    and envelope["choices"][0]["finish_reason"] == "stop" and amount <= cap):
                    charge = amount
            except (KeyError, TypeError, ValueError, IndexError):
                pass
            call.update(conservative_cost_microunits=charge, elapsed_seconds=round(monotonic() - started, 3))
            write_bundle(output / "call", {"call.json": call})

    functional_judge.bailian_complete = complete
    report = build_candidate_catalog(base / "proposal-request", config / "design.json",
        output / "compiled", evaluator_path=config / "evaluator.json")
    write_bundle(output / "summary", {"report.json": dict(report,
        actual_conservative_cost_microunits=call.get("conservative_cost_microunits", 0))})
    if retained is not None:
        assert read_json(output / "summary/report.json") == read_json(retained / "summary/report.json")
    print(json.dumps(read_json(output / "summary/report.json")), flush=True)


if __name__ == "__main__":
    run(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]) if len(sys.argv) > 3 else None)
