from app.normalization.schema import FirewallRule
from app.shadow_rules.engine import (
    analyze_shadow_rules,
)


def test_shadowed_deny_is_critical():
    rules = [
        FirewallRule(
            sequence=10,
            action="permit",
            protocol="ip",
            source="10.0.0.0/8",
            destination="0.0.0.0/0",
        ),
        FirewallRule(
            sequence=20,
            action="deny",
            protocol="ip",
            source="10.1.2.3/32",
            destination="0.0.0.0/0",
        ),
    ]

    result = analyze_shadow_rules(
        rules
    )

    assert result["summary"]["total"] == 1

    issue = result["issues"][0]

    assert issue["type"] == "shadowed_deny"
    assert issue["severity"] == "critical"
    assert issue["shadowing_sequence"] == 10
    assert issue["shadowed_sequence"] == 20


def test_redundant_allow_is_medium():
    rules = [
        FirewallRule(
            sequence=10,
            action="permit",
            protocol="ip",
            source="10.0.0.0/8",
            destination="0.0.0.0/0",
        ),
        FirewallRule(
            sequence=20,
            action="permit",
            protocol="ip",
            source="10.1.2.3/32",
            destination="0.0.0.0/0",
        ),
    ]

    result = analyze_shadow_rules(
        rules
    )

    assert result["summary"]["total"] == 1

    issue = result["issues"][0]

    assert issue["type"] == "redundant_allow"
    assert issue["severity"] == "medium"


def test_broader_later_rule_is_not_shadowed():
    rules = [
        FirewallRule(
            sequence=10,
            action="permit",
            protocol="ip",
            source="10.1.2.3/32",
            destination="0.0.0.0/0",
        ),
        FirewallRule(
            sequence=20,
            action="deny",
            protocol="ip",
            source="10.0.0.0/8",
            destination="0.0.0.0/0",
        ),
    ]

    result = analyze_shadow_rules(
        rules
    )

    assert result["summary"]["total"] == 0


def test_different_protocol_is_not_shadowed():
    rules = [
        FirewallRule(
            sequence=10,
            action="permit",
            protocol="tcp",
            source="10.0.0.0/8",
            destination="0.0.0.0/0",
        ),
        FirewallRule(
            sequence=20,
            action="deny",
            protocol="udp",
            source="10.1.2.3/32",
            destination="0.0.0.0/0",
        ),
    ]

    result = analyze_shadow_rules(
        rules
    )

    assert result["summary"]["total"] == 0


def test_disabled_earlier_rule_does_not_shadow():
    rules = [
        FirewallRule(
            sequence=10,
            action="permit",
            protocol="ip",
            source="10.0.0.0/8",
            destination="0.0.0.0/0",
            enabled=False,
        ),
        FirewallRule(
            sequence=20,
            action="deny",
            protocol="ip",
            source="10.1.2.3/32",
            destination="0.0.0.0/0",
        ),
    ]

    result = analyze_shadow_rules(
        rules
    )

    assert result["summary"]["total"] == 0