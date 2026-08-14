"""Audit envelope: что попадает в журнал и что из него вычищается."""

from __future__ import annotations

from platform_auth.audit import DecisionRecord, redact


def test_sensitive_field_names_are_redacted() -> None:
    cleaned = redact(
        {
            "authorization": "Bearer abc",
            "api_key": "cp_live_123",
            "password": "hunter2",
            "tenantId": "t-1",
        }
    )

    assert cleaned["authorization"] == "[redacted]"
    assert cleaned["api_key"] == "[redacted]"
    assert cleaned["password"] == "[redacted]"
    assert cleaned["tenantId"] == "t-1"


def test_credential_in_a_harmless_field_is_still_redacted() -> None:
    """Секрет, попавший в поле с безобидным именем, всё равно не уезжает."""
    cleaned = redact({"note": "iam_pat_abc_secret", "legacy": "cp_abc_secret"})

    assert cleaned["note"] == "[redacted]"
    assert cleaned["legacy"] == "[redacted]"


def test_nested_payload_is_cleaned() -> None:
    cleaned = redact({"outer": {"token": "eyJhbGciOi", "kept": 1}})

    assert cleaned["outer"]["token"] == "[redacted]"
    assert cleaned["outer"]["kept"] == 1


def test_upstream_subject_is_not_journalled() -> None:
    """`subject` upstream-каталога — персональные данные чужой системы."""
    cleaned = redact({"subject": "CN=ivanov,OU=users,DC=corp"})

    assert cleaned["subject"] == "[redacted]"


def test_record_without_context_still_serialises() -> None:
    record = DecisionRecord.from_context(
        None,
        outcome="denied",
        stage="identity",
        action="tasks.list",
        audience="control-plane",
        code="invalid_token",
        reason="missing_authorization",
    )

    payload = record.as_dict()

    assert payload["outcome"] == "denied"
    assert payload["principalId"] == ""
    assert payload["reason"] == "missing_authorization"
