from pathlib import Path


WORKFLOW_PATH = (
    Path(__file__).resolve().parents[1]
    / ".github"
    / "workflows"
    / "refactoring-agent.yml"
)


def test_refactoring_agent_enforces_concurrency_per_pr():
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")

    assert "concurrency:" in workflow
    assert "group: refactoring-agent-${{ github.event.issue.number }}" in workflow
    assert "cancel-in-progress: true" in workflow


def test_refactoring_agent_retries_failed_push_once():
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")

    assert "id: refactor-attempt-1" in workflow
    assert "continue-on-error: true" in workflow
    assert "Wait before retrying failed refactor" in workflow
    assert "id: refactor-attempt-2" in workflow
    assert "Fail if both refactor attempts fail" in workflow
