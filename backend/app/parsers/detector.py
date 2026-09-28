import re
from typing import Dict, List


CISCO_PATTERNS = [
    ("ios_version", r"^\s*version\s+\d+\.\d+", 3),
    ("hostname", r"^\s*hostname\s+\S+", 2),
    ("interface", r"^\s*interface\s+\S+", 2),
    ("ip_route", r"^\s*ip\s+route\s+", 2),
    ("access_list", r"^\s*access-list\s+\d+\s+", 3),
    ("ip_access_list", r"^\s*ip\s+access-list\s+", 3),
    ("line_vty", r"^\s*line\s+vty\b", 3),
    ("enable_secret", r"^\s*enable\s+secret\b", 2),
    ("ip_ssh", r"^\s*ip\s+ssh\s+", 2),
    ("service_password", r"^\s*service\s+password-encryption\b", 2),
    ("transport_input", r"^\s*transport\s+input\s+", 2),
]


PFSENSE_PATTERNS = [
    ("pfsense_root", r"<\s*pfsense(?:\s|>)", 6),
    ("system", r"<\s*system\s*>", 2),
    ("interfaces", r"<\s*interfaces\s*>", 2),
    ("filter", r"<\s*filter\s*>", 3),
    ("nat", r"<\s*nat\s*>", 2),
    ("aliases", r"<\s*aliases\s*>", 2),
    ("config_version", r"<\s*version\s*>", 1),
]


def _find_matches(
    text: str,
    patterns: List[tuple],
) -> List[Dict[str, object]]:
    matches = []

    for signal_name, pattern, weight in patterns:
        if re.search(pattern, text, re.IGNORECASE | re.MULTILINE):
            matches.append(
                {
                    "signal": signal_name,
                    "weight": weight,
                }
            )

    return matches


def detect_vendor(config_text: str) -> Dict[str, object]:
    """
    Detect the most likely vendor from a raw network configuration.

    Supported vendors:
        - Cisco IOS
        - pfSense
        - Unknown

    Detection is deterministic and evidence-based.
    """

    if not isinstance(config_text, str):
        raise TypeError("config_text must be a string")

    normalized_text = config_text.replace("\r\n", "\n").replace("\r", "\n").strip()

    if not normalized_text:
        return {
            "vendor": "unknown",
            "confidence": "low",
            "status": "unknown_vendor",
            "scores": {
                "cisco_ios": 0,
                "pfsense": 0,
            },
            "signals": [],
        }

    cisco_matches = _find_matches(normalized_text, CISCO_PATTERNS)
    pfsense_matches = _find_matches(normalized_text, PFSENSE_PATTERNS)

    cisco_score = sum(int(match["weight"]) for match in cisco_matches)
    pfsense_score = sum(int(match["weight"]) for match in pfsense_matches)

    scores = {
        "cisco_ios": cisco_score,
        "pfsense": pfsense_score,
    }

    if cisco_score == 0 and pfsense_score == 0:
        return {
            "vendor": "unknown",
            "confidence": "low",
            "status": "unknown_vendor",
            "scores": scores,
            "signals": [],
        }

    # Strong pfSense signature.
    if pfsense_score > cisco_score:
        if pfsense_score >= 6:
            confidence = "high"
        elif pfsense_score >= 3:
            confidence = "medium"
        else:
            confidence = "low"

        return {
            "vendor": "pfsense",
            "confidence": confidence,
            "status": "detected",
            "scores": scores,
            "signals": [match["signal"] for match in pfsense_matches],
        }

    # Strong Cisco signature.
    if cisco_score > pfsense_score:
        if cisco_score >= 6:
            confidence = "high"
        elif cisco_score >= 3:
            confidence = "medium"
        else:
            confidence = "low"

        return {
            "vendor": "cisco_ios",
            "confidence": confidence,
            "status": "detected",
            "scores": scores,
            "signals": [match["signal"] for match in cisco_matches],
        }

    # Same score means we don't have enough evidence to make
    # a deterministic vendor decision.
    return {
        "vendor": "unknown",
        "confidence": "low",
        "status": "ambiguous",
        "scores": scores,
        "signals": [],
    }