from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


PROJECT_ROOT = (
    Path(__file__).resolve().parents[3]
)


CISCO_SAMPLE = (
    PROJECT_ROOT
    / "sample_configs"
    / "cisco"
    / "basic_router.conf"
)

PFSENSE_SAMPLE = (
    PROJECT_ROOT
    / "sample_configs"
    / "pfsense"
    / "basic_firewall.xml"
)

UNKNOWN_SAMPLE = (
    PROJECT_ROOT
    / "sample_configs"
    / "unknown"
    / "unknown.conf"
)


def test_audit_cisco_sample():
    with CISCO_SAMPLE.open(
        "rb"
    ) as config_file:
        response = client.post(
            "/api/audit",
            files={
                "file": (
                    "basic_router.conf",
                    config_file,
                    "text/plain",
                )
            },
        )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "audit_complete"
    assert (
        data["detection"]["vendor"]
        == "cisco_ios"
    )

    assert data["normalized"] is not None
    assert data["compliance"] is not None

    assert (
        data["compliance"]["vendor"]
        == "cisco_ios"
    )

    assert (
        data["compliance"]["rule_count"]
        == 13
    )

    assert (
        data["compliance"]["summary"]["PASS"]
        == 4
    )

    assert (
        data["compliance"]["summary"]["FAIL"]
        == 4
    )

    assert (
        data["compliance"]["summary"]
        ["NOT_ASSESSED"]
        == 5
    )


def test_audit_pfsense_sample():
    with PFSENSE_SAMPLE.open(
        "rb"
    ) as config_file:
        response = client.post(
            "/api/audit",
            files={
                "file": (
                    "basic_firewall.xml",
                    config_file,
                    "application/xml",
                )
            },
        )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "audit_complete"
    assert (
        data["detection"]["vendor"]
        == "pfsense"
    )

    assert data["normalized"] is not None
    assert data["compliance"] is not None

    assert (
        data["compliance"]["vendor"]
        == "pfsense"
    )

    assert (
        data["compliance"]["rule_count"]
        == 9
    )

    assert (
        data["compliance"]["summary"]["PASS"]
        == 4
    )

    assert (
        data["compliance"]["summary"]["FAIL"]
        == 1
    )

    assert (
        data["compliance"]["summary"]
        ["NOT_ASSESSED"]
        == 4
    )


def test_audit_unknown_vendor_does_not_guess():
    with UNKNOWN_SAMPLE.open(
        "rb"
    ) as config_file:
        response = client.post(
            "/api/audit",
            files={
                "file": (
                    "unknown.conf",
                    config_file,
                    "text/plain",
                )
            },
        )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "unknown_vendor"

    assert (
        data["detection"]["vendor"]
        == "unknown"
    )

    assert data["normalized"] is None
    assert data["compliance"] is None