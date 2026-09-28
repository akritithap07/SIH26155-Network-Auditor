from fastapi.testclient import TestClient

from app.main import app


def test_cisco_shadowed_deny_appears_in_audit():
    config = """\
version 15.2
hostname shadow-router

access-list 100 permit ip 10.0.0.0 0.255.255.255 any
access-list 100 deny ip host 10.1.2.3 any
"""

    response = TestClient(app).post(
        "/api/audit",
        files={
            "file": (
                "shadow-cisco.cfg",
                config.encode("utf-8"),
                "text/plain",
            )
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["status"] == "audit_complete"

    shadow_rules = body["shadow_rules"]

    assert shadow_rules["rule_count"] == 2
    assert shadow_rules["summary"]["critical"] == 1
    assert shadow_rules["summary"]["total"] == 1

    issue = shadow_rules["issues"][0]

    assert issue["type"] == "shadowed_deny"
    assert issue["severity"] == "critical"
    assert issue["shadowing_sequence"] == 1
    assert issue["shadowed_sequence"] == 2


def test_cisco_redundant_allow_appears_in_audit():
    config = """\
version 15.2
hostname redundant-router

access-list 100 permit ip 10.0.0.0 0.255.255.255 any
access-list 100 permit ip host 10.1.2.3 any
"""

    response = TestClient(app).post(
        "/api/audit",
        files={
            "file": (
                "redundant-cisco.cfg",
                config.encode("utf-8"),
                "text/plain",
            )
        },
    )

    assert response.status_code == 200

    shadow_rules = response.json()[
        "shadow_rules"
    ]

    assert (
        shadow_rules["summary"]["medium"]
        == 1
    )

    issue = shadow_rules["issues"][0]

    assert issue["type"] == "redundant_allow"
    assert issue["severity"] == "medium"


def test_pfsense_shadowed_deny_appears_in_audit():
    config = """\
<pfsense>
  <system>
    <hostname>shadow-fw</hostname>
  </system>

  <filter>
    <rule>
      <type>pass</type>
      <interface>lan</interface>
      <protocol>tcp</protocol>
      <source>
        <network>10.0.0.0/8</network>
      </source>
      <destination>
        <any>yes</any>
      </destination>
    </rule>

    <rule>
      <type>block</type>
      <interface>lan</interface>
      <protocol>tcp</protocol>
      <source>
        <address>10.1.2.3</address>
      </source>
      <destination>
        <any>yes</any>
      </destination>
    </rule>
  </filter>
</pfsense>
"""

    response = TestClient(app).post(
        "/api/audit",
        files={
            "file": (
                "shadow-pfsense.xml",
                config.encode("utf-8"),
                "application/xml",
            )
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["detection"]["vendor"] == "pfsense"

    shadow_rules = body["shadow_rules"]

    assert shadow_rules["rule_count"] == 2
    assert shadow_rules["summary"]["critical"] == 1

    issue = shadow_rules["issues"][0]

    assert issue["type"] == "shadowed_deny"
    assert issue["severity"] == "critical"


def test_shadow_rules_do_not_change_compliance():
    config = """\
version 15.2
hostname comparison-router

access-list 100 permit ip 10.0.0.0 0.255.255.255 any
access-list 100 deny ip host 10.1.2.3 any
"""

    response = TestClient(app).post(
        "/api/audit",
        files={
            "file": (
                "comparison-cisco.cfg",
                config.encode("utf-8"),
                "text/plain",
            )
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["compliance"] is not None
    assert body["shadow_rules"] is not None

    assert set(
        finding["status"]
        for finding in body["compliance"]["findings"]
    ) <= {
        "PASS",
        "FAIL",
        "NOT_ASSESSED",
    }