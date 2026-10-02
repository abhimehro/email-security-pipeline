"""Tests for daily repository-automation status publication policy."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / ".github" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import repository_automation_tasks as tasks  # noqa: E402


def test_status_issue_publication_defaults_to_enabled() -> None:
    assert tasks.should_publish_status_issue({}, "success") is True


def test_status_issue_publication_can_be_disabled() -> None:
    assert tasks.should_publish_status_issue({"publish_issue": False}, "failure") is False


def test_success_only_suppression_preserves_actionable_reports() -> None:
    section = {"publish_issue": True, "publish_on_success": False}

    assert tasks.should_publish_status_issue(section, "success") is False
    assert tasks.should_publish_status_issue(section, "warning") is True
    assert tasks.should_publish_status_issue(section, "failure") is True


def test_successful_daily_report_skips_issue_creation() -> None:
    config = {
        "reporting": {"daily_issue_prefix": "Daily report"},
        "status_report": {"publish_issue": True, "publish_on_success": False},
    }
    with (
        patch.object(tasks, "load_task_results", return_value=[{"status": "success"}]),
        patch.object(tasks, "daily_report_lines", return_value=["report"]),
        patch.object(tasks, "append_publication_result") as publish,
        patch.object(tasks, "write_result", return_value={"status": "success"}) as write,
    ):
        result = tasks.run_daily_status_report(config)

    publish.assert_not_called()
    assert result == {"status": "success"}
    assert "no actionable findings" in write.call_args.args[2]
    assert write.call_args.args[3]["issue_url"] == ""
