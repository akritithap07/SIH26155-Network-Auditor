from pathlib import Path

from fastapi.testclient import TestClient

import app.api.analysis as analysis_api
from app.learning.store import LearningStore
from app.learning.trainer import SemanticMapper
from app.main import app


class FakeAuditMapper:
    def __init__(self, learned=False):
        self.learned = learned
        self.calls = []

    def suggest(
        self,
        vendor,
        source_text,
        top_k=3,
    ):
        self.calls.append(
            {
                "vendor": vendor,
                "source_text": source_text,
                "top_k": top_k,
            }
        )

        return [
            {
                "vendor": vendor,
                "control_id": (
                    "CIS-NET-03"
                    if vendor == "cisco_ios"
                    else "CIS-NET-19"
                ),
                "target_key": (
                    "security.ssh_version"
                    if vendor == "cisco_ios"
                    else (
                        "security."
                        "firewall_allow_any_service"
                    )
                ),
                "example": source_text,
                "description": "Test AI suggestion.",
                "score": 0.91,
                "confidence_band": "high",
                "match_source": (
                    "learned"
                    if self.learned
                    else "seed"
                ),
                "learned": self.learned,
            }
        ]


class FailingAuditMapper:
    def suggest(
        self,
        vendor,
        source_text,
        top_k=3,
    ):
        raise RuntimeError(
            "simulated mapper failure"
        )


def test_cisco_unknown_entry_gets_ai_assistance(
    monkeypatch,
):
    mapper = FakeAuditMapper()

    monkeypatch.setattr(
        analysis_api,
        "get_mapper",
        lambda: mapper,
    )

    config = """\
hostname edge-router
force the router to use SSH protocol version two
"""

    response = TestClient(app).post(
        "/api/audit",
        files={
            "file": (
                "unknown-cisco.cfg",
                config.encode("utf-8"),
                "text/plain",
            )
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["status"] == "audit_complete"
    assert (
        body["ai_assistance"]["status"]
        == "available"
    )
    assert (
        body["ai_assistance"]["entry_count"]
        == 1
    )

    ai_entry = body["ai_assistance"]["entries"][0]

    assert (
        ai_entry["text"]
        == "force the router to use SSH protocol version two"
    )

    assert (
        ai_entry["suggestions"][0]["control_id"]
        == "CIS-NET-03"
    )

    assert (
        body["ai_assistance"][
            "impact_on_compliance"
        ]
        == "none"
    )

    assert (
        len(
            body["normalized"][
                "unrecognized_entries"
            ]
        )
        == 1
    )


def test_learned_mapping_is_exposed_by_audit(
    tmp_path: Path,
    monkeypatch,
):
    store = LearningStore(
        db_path=tmp_path / "learning.db"
    )

    class SingleVectorModel:
        def encode(
            self,
            texts,
            normalize_embeddings=True,
        ):
            if isinstance(texts, str):
                return [1.0, 0.0, 0.0]

            return [
                [1.0, 0.0, 0.0]
                for _ in texts
            ]

    mapper = SemanticMapper(
        store=store,
        model=SingleVectorModel(),
    )

    mapper.confirm(
        vendor="cisco_ios",
        source_text=(
            "force the router to use SSH protocol version two"
        ),
        candidate={
            "control_id": "CIS-NET-03",
            "target_key": "security.ssh_version",
            "score": 0.67,
            "description": (
                "Human confirmed SSH version 2."
            ),
        },
    )

    monkeypatch.setattr(
        analysis_api,
        "get_mapper",
        lambda: mapper,
    )

    response = TestClient(app).post(
        "/api/audit",
        files={
            "file": (
                "learned-cisco.cfg",
                (
                    "hostname edge-router\n"
                    "force the router to use SSH protocol version two\n"
                ).encode("utf-8"),
                "text/plain",
            )
        },
    )

    assert response.status_code == 200

    candidate = response.json()[
        "ai_assistance"
    ]["entries"][0]["suggestions"][0]

    assert (
        candidate["match_source"]
        == "learned"
    )
    assert candidate["learned"] is True
    assert candidate["score"] == 1.0


def test_pfsense_unknown_rule_field_gets_ai_assistance(
    monkeypatch,
):
    mapper = FakeAuditMapper()

    monkeypatch.setattr(
        analysis_api,
        "get_mapper",
        lambda: mapper,
    )

    config = """\
<pfsense>
  <system>
    <hostname>fw</hostname>
    <ssh>
      <enabled>yes</enabled>
    </ssh>
    <webgui>
      <protocol>https</protocol>
    </webgui>
  </system>
  <filter>
    <rule>
      <type>pass</type>
      <interface>lan</interface>
      <protocol>tcp</protocol>
      <custom-option>future-value</custom-option>
    </rule>
  </filter>
</pfsense>
"""

    response = TestClient(app).post(
        "/api/audit",
        files={
            "file": (
                "unknown-pfsense.xml",
                config.encode("utf-8"),
                "application/xml",
            )
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert (
        body["detection"]["vendor"]
        == "pfsense"
    )

    assert (
        body["ai_assistance"]["entry_count"]
        == 1
    )

    ai_entry = body["ai_assistance"]["entries"][0]

    assert "custom-option" in ai_entry["text"]
    assert (
        ai_entry["context"]
        == "filter.rule[1]"
    )

    assert (
        ai_entry["suggestions"][0]["control_id"]
        == "CIS-NET-19"
    )

    assert (
        body["ai_assistance"][
            "impact_on_compliance"
        ]
        == "none"
    )


def test_ai_failure_does_not_break_audit(
    monkeypatch,
):
    monkeypatch.setattr(
        analysis_api,
        "get_mapper",
        lambda: FailingAuditMapper(),
    )

    config = """\
hostname edge-router
unknown hardening command
"""

    response = TestClient(app).post(
        "/api/audit",
        files={
            "file": (
                "ai-failure.cfg",
                config.encode("utf-8"),
                "text/plain",
            )
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["status"] == "audit_complete"
    assert (
        body["ai_assistance"]["status"]
        == "degraded"
    )
    assert (
        body["ai_assistance"][
            "impact_on_compliance"
        ]
        == "none"
    )
    assert body["compliance"] is not None
    assert (
        body["ai_assistance"]["entries"][0][
            "suggestions"
        ]
        == []
    )