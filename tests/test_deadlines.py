"""Tests for CRA deadline tracking engine."""

import json
import os
import pytest

from agent.deadlines import (
    compute_deadline,
    deadline_status,
    days_remaining,
    build_deadline_entry,
    compute_deadlines_for_findings,
    summarize_deadlines,
    format_deadlines_table,
    compute_notification_milestones,
    escalation_level,
    format_escalation_summary,
    DEADLINE_DAYS,
    NOTIFICATION_MILESTONES,
)
from agent.models import Finding


def _make_finding(cve="CVE-2024-1234", severity="high", package="flask"):
    return Finding(
        id=cve,
        source_scanner="trivy_fs",
        finding_type="language_dep",
        severity=severity,
        title=f"Test vuln in {package}",
        package=package,
        installed_version="1.0.0",
    )


# --- compute_deadline ---

class TestComputeDeadline:
    def test_critical_24h(self):
        assert compute_deadline("critical", "2026-04-04") == "2026-04-05"

    def test_high_7d(self):
        assert compute_deadline("high", "2026-04-04") == "2026-04-11"

    def test_medium_30d(self):
        assert compute_deadline("medium", "2026-04-04") == "2026-05-04"

    def test_low_90d(self):
        assert compute_deadline("low", "2026-04-04") == "2026-07-03"

    def test_info_90d(self):
        assert compute_deadline("info", "2026-04-04") == "2026-07-03"

    def test_unknown_severity_defaults_90d(self):
        assert compute_deadline("unknown", "2026-04-04") == "2026-07-03"

    def test_case_insensitive(self):
        assert compute_deadline("CRITICAL", "2026-04-04") == "2026-04-05"


# --- deadline_status ---

class TestDeadlineStatus:
    def test_overdue(self):
        assert deadline_status("2026-04-01", as_of="2026-04-04") == "overdue"

    def test_warning_within_3_days(self):
        assert deadline_status("2026-04-06", as_of="2026-04-04") == "warning"

    def test_warning_on_deadline_day(self):
        assert deadline_status("2026-04-04", as_of="2026-04-04") == "warning"

    def test_open(self):
        assert deadline_status("2026-05-04", as_of="2026-04-04") == "open"

    def test_exactly_3_days(self):
        assert deadline_status("2026-04-07", as_of="2026-04-04") == "warning"

    def test_4_days_is_open(self):
        assert deadline_status("2026-04-08", as_of="2026-04-04") == "open"


# --- days_remaining ---

class TestDaysRemaining:
    def test_positive(self):
        assert days_remaining("2026-04-14", as_of="2026-04-04") == 10

    def test_negative_overdue(self):
        assert days_remaining("2026-04-01", as_of="2026-04-04") == -3

    def test_zero_on_deadline_day(self):
        assert days_remaining("2026-04-04", as_of="2026-04-04") == 0


# --- build_deadline_entry ---

class TestBuildDeadlineEntry:
    def test_builds_entry(self):
        f = _make_finding(severity="high")
        entry = build_deadline_entry(f, "2026-04-04")
        assert entry["cve"] == "CVE-2024-1234"
        assert entry["package"] == "flask"
        assert entry["severity"] == "high"
        assert entry["discovered_at"] == "2026-04-04"
        assert entry["deadline"] == "2026-04-11"
        assert entry["deadline_days"] == 7

    def test_critical_deadline(self):
        f = _make_finding(severity="critical")
        entry = build_deadline_entry(f, "2026-04-04")
        assert entry["deadline"] == "2026-04-05"
        assert entry["deadline_days"] == 1


# --- compute_deadlines_for_findings ---

class TestComputeDeadlinesForFindings:
    def test_adds_new_findings(self):
        f1 = _make_finding(cve="CVE-2024-001", severity="high")
        f2 = _make_finding(cve="CVE-2024-002", severity="medium")
        result = compute_deadlines_for_findings([f1, f2], {}, today="2026-04-04")
        assert len(result) == 2

    def test_preserves_existing(self):
        f1 = _make_finding(cve="CVE-2024-001", severity="high")
        existing = {
            f1.fingerprint(): {
                "cve": "CVE-2024-001",
                "discovered_at": "2026-03-01",
                "deadline": "2026-03-08",
            }
        }
        result = compute_deadlines_for_findings([f1], existing, today="2026-04-04")
        # Should keep the original discovered_at, not update to today
        assert result[f1.fingerprint()]["discovered_at"] == "2026-03-01"

    def test_does_not_duplicate(self):
        f1 = _make_finding()
        result1 = compute_deadlines_for_findings([f1], {}, today="2026-04-04")
        result2 = compute_deadlines_for_findings([f1], result1, today="2026-04-05")
        assert len(result2) == 1
        assert result2[f1.fingerprint()]["discovered_at"] == "2026-04-04"


# --- summarize_deadlines ---

class TestSummarizeDeadlines:
    def test_empty(self):
        s = summarize_deadlines({})
        assert s["total"] == 0
        assert s["overdue"] == 0

    def test_mixed_statuses(self):
        dl = {
            "fp1": {"cve": "CVE-001", "severity": "critical", "deadline": "2026-04-01", "package": "a"},
            "fp2": {"cve": "CVE-002", "severity": "high", "deadline": "2026-04-06", "package": "b"},
            "fp3": {"cve": "CVE-003", "severity": "medium", "deadline": "2026-05-04", "package": "c"},
            "fp4": {"cve": "CVE-004", "severity": "low", "status": "met", "deadline": "2026-03-01", "package": "d"},
        }
        s = summarize_deadlines(dl, as_of="2026-04-04")
        assert s["overdue"] == 1
        assert s["warning"] == 1
        assert s["open"] == 1
        assert s["met"] == 1
        assert s["total"] == 4
        assert len(s["overdue_findings"]) == 1
        assert s["overdue_findings"][0]["cve"] == "CVE-001"

    def test_overdue_sorted_by_days(self):
        dl = {
            "fp1": {"cve": "CVE-A", "severity": "high", "deadline": "2026-03-01", "package": "x"},
            "fp2": {"cve": "CVE-B", "severity": "high", "deadline": "2026-04-01", "package": "y"},
        }
        s = summarize_deadlines(dl, as_of="2026-04-04")
        assert s["overdue_findings"][0]["cve"] == "CVE-A"  # More overdue first


# --- format_deadlines_table ---

class TestFormatDeadlinesTable:
    def test_empty(self):
        result = format_deadlines_table({})
        assert "No CRA deadlines" in result

    def test_has_content(self):
        dl = {
            "fp1": {"cve": "CVE-001", "severity": "critical", "deadline": "2026-04-01", "package": "flask"},
        }
        result = format_deadlines_table(dl, as_of="2026-04-04")
        assert "OVERDUE" in result
        assert "CVE-001" in result


# --- compute_notification_milestones ---

class TestComputeNotificationMilestones:
    def test_early_warning_24h(self):
        result = compute_notification_milestones("2026-04-04")
        assert result["early_warning_24h"] == "2026-04-05"

    def test_notification_72h(self):
        result = compute_notification_milestones("2026-04-04")
        assert result["notification_72h"] == "2026-04-07"

    def test_final_report_14d(self):
        result = compute_notification_milestones("2026-04-04")
        assert result["final_report_14d"] == "2026-04-18"

    def test_all_three_keys_present(self):
        result = compute_notification_milestones("2026-04-04")
        assert set(result.keys()) == {"early_warning_24h", "notification_72h", "final_report_14d"}

    def test_month_boundary(self):
        result = compute_notification_milestones("2026-04-30")
        assert result["early_warning_24h"] == "2026-05-01"
        assert result["notification_72h"] == "2026-05-03"
        assert result["final_report_14d"] == "2026-05-14"


# --- escalation_level ---

def _make_entry(notifications: dict, cve="CVE-2024-1234", package="flask") -> dict:
    """Build a minimal deadline entry with the given notifications dict."""
    return {
        "cve": cve,
        "package": package,
        "severity": "high",
        "discovered_at": "2026-04-01",
        "deadline": "2026-04-08",
        "notifications": notifications,
    }


class TestEscalationLevel:
    def test_no_milestones_overdue_returns_none(self):
        notifications = {
            "early_warning_24h": {"due": "2026-04-10", "sent": None},
            "notification_72h": {"due": "2026-04-12", "sent": None},
            "final_report_14d": {"due": "2026-04-20", "sent": None},
        }
        entry = _make_entry(notifications)
        assert escalation_level(entry, as_of="2026-04-04") == "none"

    def test_final_report_overdue_returns_warning(self):
        notifications = {
            "early_warning_24h": {"due": "2026-04-02", "sent": "2026-04-02"},
            "notification_72h": {"due": "2026-04-04", "sent": "2026-04-04"},
            "final_report_14d": {"due": "2026-04-10", "sent": None},
        }
        entry = _make_entry(notifications)
        assert escalation_level(entry, as_of="2026-04-15") == "warning"

    def test_notification_72h_overdue_returns_escalated(self):
        notifications = {
            "early_warning_24h": {"due": "2026-04-02", "sent": "2026-04-02"},
            "notification_72h": {"due": "2026-04-04", "sent": None},
            "final_report_14d": {"due": "2026-04-15", "sent": None},
        }
        entry = _make_entry(notifications)
        assert escalation_level(entry, as_of="2026-04-10") == "escalated"

    def test_early_warning_overdue_returns_critical(self):
        notifications = {
            "early_warning_24h": {"due": "2026-04-02", "sent": None},
            "notification_72h": {"due": "2026-04-04", "sent": None},
            "final_report_14d": {"due": "2026-04-15", "sent": None},
        }
        entry = _make_entry(notifications)
        assert escalation_level(entry, as_of="2026-04-10") == "critical"

    def test_sent_milestone_is_skipped_even_if_overdue(self):
        # 24h overdue but sent — should fall through to next level
        notifications = {
            "early_warning_24h": {"due": "2026-04-02", "sent": "2026-04-02"},
            "notification_72h": {"due": "2026-04-04", "sent": None},
            "final_report_14d": {"due": "2026-04-15", "sent": None},
        }
        entry = _make_entry(notifications)
        assert escalation_level(entry, as_of="2026-04-10") == "escalated"

    def test_all_sent_returns_none(self):
        notifications = {
            "early_warning_24h": {"due": "2026-04-02", "sent": "2026-04-02"},
            "notification_72h": {"due": "2026-04-04", "sent": "2026-04-04"},
            "final_report_14d": {"due": "2026-04-15", "sent": "2026-04-15"},
        }
        entry = _make_entry(notifications)
        assert escalation_level(entry, as_of="2026-04-20") == "none"

    def test_no_notifications_key_returns_none(self):
        entry = {"cve": "CVE-X", "package": "pkg", "deadline": "2026-04-08"}
        assert escalation_level(entry, as_of="2026-04-20") == "none"


# --- format_escalation_summary ---

class TestFormatEscalationSummary:
    def test_empty_returns_on_track_message(self):
        result = format_escalation_summary({})
        assert "on track" in result.lower()

    def test_all_on_track_returns_no_alerts(self):
        notifications = {
            "early_warning_24h": {"due": "2026-04-10", "sent": None},
            "notification_72h": {"due": "2026-04-12", "sent": None},
            "final_report_14d": {"due": "2026-04-20", "sent": None},
        }
        deadlines = {"fp1": _make_entry(notifications, cve="CVE-001")}
        result = format_escalation_summary(deadlines, as_of="2026-04-04")
        assert "on track" in result.lower()

    def test_critical_finding_appears_under_critical_heading(self):
        notifications = {
            "early_warning_24h": {"due": "2026-04-02", "sent": None},
            "notification_72h": {"due": "2026-04-04", "sent": None},
            "final_report_14d": {"due": "2026-04-15", "sent": None},
        }
        deadlines = {"fp1": _make_entry(notifications, cve="CVE-9999")}
        result = format_escalation_summary(deadlines, as_of="2026-04-10")
        assert "CRITICAL" in result
        assert "CVE-9999" in result

    def test_mixed_levels_all_appear(self):
        # critical entry
        n_critical = {
            "early_warning_24h": {"due": "2026-04-02", "sent": None},
            "notification_72h": {"due": "2026-04-04", "sent": None},
            "final_report_14d": {"due": "2026-04-15", "sent": None},
        }
        # warning entry (24h and 72h sent, 14d overdue)
        n_warning = {
            "early_warning_24h": {"due": "2026-04-02", "sent": "2026-04-02"},
            "notification_72h": {"due": "2026-04-04", "sent": "2026-04-04"},
            "final_report_14d": {"due": "2026-04-10", "sent": None},
        }
        deadlines = {
            "fp1": _make_entry(n_critical, cve="CVE-CRIT"),
            "fp2": _make_entry(n_warning, cve="CVE-WARN"),
        }
        result = format_escalation_summary(deadlines, as_of="2026-04-20")
        assert "CVE-CRIT" in result
        assert "CVE-WARN" in result
        assert "CRITICAL" in result
        assert "WARNING" in result

    def test_overdue_hours_shown_for_recent_overdue(self):
        # 2 days overdue → 48h; show days
        notifications = {
            "early_warning_24h": {"due": "2026-04-08", "sent": None},
            "notification_72h": {"due": "2026-04-10", "sent": None},
            "final_report_14d": {"due": "2026-04-20", "sent": None},
        }
        deadlines = {"fp1": _make_entry(notifications, cve="CVE-T")}
        result = format_escalation_summary(deadlines, as_of="2026-04-10")
        assert "CVE-T" in result


# --- TestNotificationMilestonesInDeadlineEntry ---

class TestNotificationMilestonesInDeadlineEntry:
    def test_notifications_key_present(self):
        f = _make_finding(severity="high")
        entry = build_deadline_entry(f, "2026-04-04")
        assert "notifications" in entry

    def test_all_three_milestones_present(self):
        f = _make_finding(severity="high")
        entry = build_deadline_entry(f, "2026-04-04")
        notifs = entry["notifications"]
        assert "early_warning_24h" in notifs
        assert "notification_72h" in notifs
        assert "final_report_14d" in notifs

    def test_milestone_due_dates_correct(self):
        f = _make_finding(severity="high")
        entry = build_deadline_entry(f, "2026-04-04")
        notifs = entry["notifications"]
        assert notifs["early_warning_24h"]["due"] == "2026-04-05"
        assert notifs["notification_72h"]["due"] == "2026-04-07"
        assert notifs["final_report_14d"]["due"] == "2026-04-18"

    def test_all_sent_fields_are_none(self):
        f = _make_finding(severity="critical")
        entry = build_deadline_entry(f, "2026-04-04")
        for ms_name, ms_data in entry["notifications"].items():
            assert ms_data["sent"] is None, f"{ms_name} sent should be None"


# --- TestSummarizeDeadlinesWithEscalation ---

class TestSummarizeDeadlinesWithEscalation:
    def test_escalation_counts_present_in_summary(self):
        dl = {
            "fp1": {"cve": "CVE-001", "severity": "high", "deadline": "2026-05-01", "package": "a",
                    "notifications": {
                        "early_warning_24h": {"due": "2026-04-05", "sent": None},
                        "notification_72h": {"due": "2026-04-07", "sent": None},
                        "final_report_14d": {"due": "2026-04-18", "sent": None},
                    }},
        }
        s = summarize_deadlines(dl, as_of="2026-04-20")
        assert "escalation_counts" in s
        assert "escalation_findings" in s

    def test_escalation_counts_correct(self):
        # One critical (24h overdue, unsent), one clean
        n_critical = {
            "early_warning_24h": {"due": "2026-04-02", "sent": None},
            "notification_72h": {"due": "2026-04-04", "sent": None},
            "final_report_14d": {"due": "2026-04-15", "sent": None},
        }
        n_clean = {
            "early_warning_24h": {"due": "2026-04-10", "sent": None},
            "notification_72h": {"due": "2026-04-12", "sent": None},
            "final_report_14d": {"due": "2026-04-20", "sent": None},
        }
        dl = {
            "fp1": {"cve": "CVE-A", "severity": "high", "deadline": "2026-05-01", "package": "a",
                    "notifications": n_critical},
            "fp2": {"cve": "CVE-B", "severity": "medium", "deadline": "2026-05-10", "package": "b",
                    "notifications": n_clean},
        }
        s = summarize_deadlines(dl, as_of="2026-04-10")
        assert s["escalation_counts"]["critical"] == 1
        assert s["escalation_counts"]["escalated"] == 0
        assert s["escalation_counts"]["warning"] == 0
        assert len(s["escalation_findings"]) == 1
        assert s["escalation_findings"][0]["cve"] == "CVE-A"
        assert s["escalation_findings"][0]["level"] == "critical"

    def test_empty_deadlines_has_zero_escalations(self):
        s = summarize_deadlines({})
        assert s["escalation_counts"] == {"critical": 0, "escalated": 0, "warning": 0}
        assert s["escalation_findings"] == []


# --- State integration ---

class TestStateIntegration:
    def test_close_marks_deadline_met(self, tmp_path):
        from agent.state import load_state, save_state, close_finding, load_deadlines

        project = str(tmp_path)
        os.makedirs(os.path.join(project, ".patchpilot"))

        f = _make_finding()
        fp = f.fingerprint()

        # Set up state with a deadline
        state = load_state(project)
        state["cra_deadlines"][fp] = {
            "cve": f.id,
            "deadline": "2026-04-11",
            "discovered_at": "2026-04-04",
        }
        save_state(project, state)

        # Close the finding
        close_finding(project, f, reason="upgraded")

        # Verify deadline is marked as met
        dl = load_deadlines(project)
        assert dl[fp]["status"] == "met"
        assert "met_at" in dl[fp]
