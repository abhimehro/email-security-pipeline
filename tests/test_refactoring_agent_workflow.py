from pathlib import Path

import yaml


WORKFLOW_PATH = (
    Path(__file__).resolve().parents[1]
    / ".github"
    / "workflows"
    / "refactoring-agent.yml"
)


def load_workflow():
    return yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))


def test_refactoring_agent_enforces_concurrency_per_pr():
    workflow = load_workflow()

    assert workflow["concurrency"] == {
        "group": "refactoring-agent-${{ github.event.issue.number }}",
        "cancel-in-progress": True,
    }


def test_refactoring_agent_retries_failed_push_once():
    steps = load_workflow()["jobs"]["refactor"]["steps"]
    steps_by_id = {step["id"]: step for step in steps if "id" in step}
    steps_by_name = {step["name"]: step for step in steps if "name" in step}

    assert steps_by_id["refactor-attempt-1"]["continue-on-error"] is True
    assert (
        steps_by_name["Wait before retrying failed refactor"]["if"]
        == "steps.refactor-attempt-1.outcome == 'failure'"
    )
    assert steps_by_name["Wait before retrying failed refactor"]["env"] == {
        "REFACTOR_RETRY_DELAY_SECONDS": 15
    }
    assert (
        steps_by_name["Wait before retrying failed refactor"]["run"]
        == 'sleep "${REFACTOR_RETRY_DELAY_SECONDS}"'
    )
    assert (
        steps_by_id["refactor-attempt-2"]["if"]
        == "steps.refactor-attempt-1.outcome == 'failure'"
    )
    assert steps_by_id["refactor-attempt-2"]["continue-on-error"] is True
    assert (
        steps_by_name["Fail if both refactor attempts fail"]["if"]
        == "always() && steps.refactor-attempt-1.outcome == 'failure' && steps.refactor-attempt-2.outcome == 'failure'"
    )
