import ipaddress
from typing import Any, Dict, List, Optional, Tuple

from app.normalization.schema import FirewallRule


ALLOW_ACTIONS = {
    "allow",
    "pass",
    "permit",
}

DENY_ACTIONS = {
    "deny",
    "block",
    "reject",
}


def _rule_value(
    rule: Any,
    field: str,
    default: Any = None,
) -> Any:
    if isinstance(rule, dict):
        return rule.get(field, default)

    return getattr(
        rule,
        field,
        default,
    )


def _normalized_action(
    rule: Any,
) -> Optional[str]:
    action = _rule_value(
        rule,
        "action",
    )

    if action is None:
        return None

    normalized = str(
        action
    ).strip().lower()

    if normalized in ALLOW_ACTIONS:
        return "allow"

    if normalized in DENY_ACTIONS:
        return "deny"

    return None


def _is_enabled(
    rule: Any,
) -> bool:
    value = _rule_value(
        rule,
        "enabled",
        True,
    )

    return value is not False


def _is_any_value(
    value: Optional[str],
) -> bool:
    if value is None:
        return True

    normalized = str(
        value
    ).strip().lower()

    return normalized in {
        "",
        "any",
        "0.0.0.0/0",
        "::/0",
    }


def _parse_network(
    value: Optional[str],
) -> Optional[ipaddress._BaseNetwork]:
    if _is_any_value(value):
        return ipaddress.ip_network(
            "0.0.0.0/0"
        )

    if value is None:
        return None

    normalized = str(
        value
    ).strip()

    try:
        return ipaddress.ip_network(
            normalized,
            strict=False,
        )
    except ValueError:
        pass

    try:
        return ipaddress.ip_network(
            f"{normalized}/32",
            strict=False,
        )
    except ValueError:
        return None


def _network_contains(
    earlier: Optional[str],
    later: Optional[str],
) -> bool:
    """
    Return True when the earlier rule's address scope fully
    contains the later rule's address scope.

    Unknown/non-IP expressions only match exact strings so that
    the detector stays conservative.
    """
    if _is_any_value(earlier):
        return True

    if _is_any_value(later):
        return False

    earlier_network = _parse_network(
        earlier
    )
    later_network = _parse_network(
        later
    )

    if (
        earlier_network is not None
        and later_network is not None
    ):
        return (
            later_network.subnet_of(
                earlier_network
            )
        )

    if earlier is None or later is None:
        return False

    return (
        str(earlier).strip().lower()
        == str(later).strip().lower()
    )


def _parse_port_scope(
    value: Optional[str],
) -> Optional[Tuple[str, int, int]]:
    if value is None:
        return ("any", 0, 65535)

    normalized = str(
        value
    ).strip().lower()

    if not normalized:
        return ("any", 0, 65535)

    if normalized in {
        "any",
        "any port",
    }:
        return ("any", 0, 65535)

    parts = normalized.split()

    if not parts:
        return ("any", 0, 65535)

    operator = parts[0]

    if operator == "eq" and len(parts) >= 2:
        try:
            port = int(parts[1])
            return ("range", port, port)
        except ValueError:
            return ("unknown", 0, 0)

    if operator == "range" and len(parts) >= 3:
        try:
            start = int(parts[1])
            end = int(parts[2])
            return (
                "range",
                min(start, end),
                max(start, end),
            )
        except ValueError:
            return ("unknown", 0, 0)

    try:
        port = int(parts[0])
        return ("range", port, port)
    except ValueError:
        return ("token", 0, 0)


def _port_scope_contains(
    earlier: Optional[str],
    later: Optional[str],
) -> bool:
    earlier_scope = _parse_port_scope(
        earlier
    )
    later_scope = _parse_port_scope(
        later
    )

    if earlier_scope is None:
        return False

    if later_scope is None:
        return False

    if earlier_scope[0] == "any":
        return True

    if later_scope[0] == "any":
        return False

    if (
        earlier_scope[0] == "range"
        and later_scope[0] == "range"
    ):
        return (
            earlier_scope[1] <= later_scope[1]
            and earlier_scope[2] >= later_scope[2]
        )

    if (
        earlier_scope[0] == "token"
        and later_scope[0] == "token"
    ):
        return earlier == later

    return False


def _value_contains(
    earlier: Optional[str],
    later: Optional[str],
) -> bool:
    """
    Compare fields where an absent/any earlier value is broader.
    """
    if earlier is None:
        return True

    if later is None:
        return False

    return (
        str(earlier).strip().lower()
        == str(later).strip().lower()
    )


def _protocol_contains(
    earlier: Optional[str],
    later: Optional[str],
) -> bool:
    if earlier is None:
        return True

    normalized_earlier = str(
        earlier
    ).strip().lower()

    if normalized_earlier in {
        "",
        "any",
        "ip",
    }:
        return True

    if later is None:
        return False

    normalized_later = str(
        later
    ).strip().lower()

    return (
        normalized_earlier
        == normalized_later
    )


def _rule_contains(
    earlier: Any,
    later: Any,
) -> bool:
    """
    Determine whether every traffic match of the later rule
    is also matched by the earlier rule.

    This is deliberately conservative.
    """
    if not _network_contains(
        _rule_value(earlier, "source"),
        _rule_value(later, "source"),
    ):
        return False

    if not _network_contains(
        _rule_value(earlier, "destination"),
        _rule_value(later, "destination"),
    ):
        return False

    if not _protocol_contains(
        _rule_value(earlier, "protocol"),
        _rule_value(later, "protocol"),
    ):
        return False

    if not _port_scope_contains(
        _rule_value(earlier, "source_port"),
        _rule_value(later, "source_port"),
    ):
        return False

    if not _port_scope_contains(
        _rule_value(earlier, "destination_port"),
        _rule_value(later, "destination_port"),
    ):
        return False

    if not _value_contains(
        _rule_value(earlier, "interface"),
        _rule_value(later, "interface"),
    ):
        return False

    if not _value_contains(
        _rule_value(earlier, "direction"),
        _rule_value(later, "direction"),
    ):
        return False

    return True


def _sequence_value(
    rule: Any,
    fallback: int,
) -> int:
    sequence = _rule_value(
        rule,
        "sequence",
    )

    if sequence is None:
        return fallback

    try:
        return int(sequence)
    except (
        TypeError,
        ValueError,
    ):
        return fallback


def _rule_label(
    rule: Any,
    fallback_index: int,
) -> str:
    sequence = _sequence_value(
        rule,
        fallback_index,
    )

    name = _rule_value(
        rule,
        "name",
    )

    if name:
        return (
            f"{name} "
            f"(sequence {sequence})"
        )

    return f"Rule sequence {sequence}"


def analyze_shadow_rules(
    firewall_rules: List[
        FirewallRule
    ],
) -> Dict[str, Any]:
    """
    Detect basic rule shadowing/redundancy.

    The rules are evaluated in priority order. A later rule is
    considered shadowed only when an earlier rule completely
    contains its traffic scope.

    MVP classifications:
      - later DENY fully covered by earlier ALLOW -> Critical
      - later ALLOW fully covered by earlier ALLOW -> Medium
    """
    ordered_rules = sorted(
        enumerate(firewall_rules),
        key=lambda item: (
            _sequence_value(
                item[1],
                item[0] + 1,
            ),
            item[0],
        ),
    )

    issues: List[Dict[str, Any]] = []

    for later_position in range(
        len(ordered_rules)
    ):
        later_original_index, later_rule = (
            ordered_rules[later_position]
        )

        if not _is_enabled(later_rule):
            continue

        later_action = _normalized_action(
            later_rule
        )

        if later_action not in {
            "allow",
            "deny",
        }:
            continue

        for earlier_position in range(
            later_position
        ):
            earlier_original_index, earlier_rule = (
                ordered_rules[
                    earlier_position
                ]
            )

            if not _is_enabled(
                earlier_rule
            ):
                continue

            earlier_action = _normalized_action(
                earlier_rule
            )

            if earlier_action != "allow":
                continue

            if not _rule_contains(
                earlier_rule,
                later_rule,
            ):
                continue

            earlier_sequence = _sequence_value(
                earlier_rule,
                earlier_original_index + 1,
            )

            later_sequence = _sequence_value(
                later_rule,
                later_original_index + 1,
            )

            if later_action == "deny":
                issues.append(
                    {
                        "type": "shadowed_deny",
                        "severity": "critical",
                        "shadowing_sequence": (
                            earlier_sequence
                        ),
                        "shadowed_sequence": (
                            later_sequence
                        ),
                        "shadowing_rule": _rule_label(
                            earlier_rule,
                            earlier_original_index + 1,
                        ),
                        "shadowed_rule": _rule_label(
                            later_rule,
                            later_original_index + 1,
                        ),
                        "reason": (
                            "An earlier ALLOW rule "
                            "matches the entire scope "
                            "of this later DENY rule, "
                            "so the DENY cannot take "
                            "effect."
                        ),
                        "remediation": (
                            "Move the DENY rule above "
                            "the broader ALLOW rule or "
                            "narrow the earlier ALLOW scope."
                        ),
                    }
                )

                break

            if later_action == "allow":
                issues.append(
                    {
                        "type": "redundant_allow",
                        "severity": "medium",
                        "shadowing_sequence": (
                            earlier_sequence
                        ),
                        "shadowed_sequence": (
                            later_sequence
                        ),
                        "shadowing_rule": _rule_label(
                            earlier_rule,
                            earlier_original_index + 1,
                        ),
                        "shadowed_rule": _rule_label(
                            later_rule,
                            later_original_index + 1,
                        ),
                        "reason": (
                            "An earlier ALLOW rule "
                            "already permits the entire "
                            "scope of this later ALLOW rule."
                        ),
                        "remediation": (
                            "Remove the redundant ALLOW "
                            "rule or narrow its scope if "
                            "it is intended to document a "
                            "specific exception."
                        ),
                    }
                )

                break

    return {
        "rule_count": len(
            firewall_rules
        ),
        "issues": issues,
        "summary": {
            "critical": sum(
                1
                for issue in issues
                if issue["severity"]
                == "critical"
            ),
            "medium": sum(
                1
                for issue in issues
                if issue["severity"]
                == "medium"
            ),
            "total": len(issues),
        },
    }