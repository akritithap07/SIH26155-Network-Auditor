from typing import Any, Dict, List

from app.compliance.rules import COMPLIANCE_RULES
from app.normalization.schema import NormalizedConfig


VALID_STATUSES = {
    "PASS",
    "FAIL",
    "NOT_ASSESSED",
}

SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


def run_compliance(
    normalized_config: NormalizedConfig,
) -> Dict[str, Any]:
    """
    Evaluate the normalized configuration against deterministic
    compliance rules.

    The engine never guesses missing evidence. When the normalized
    configuration does not contain enough information to make a
    reliable decision, the result is NOT_ASSESSED.
    """

    vendor = normalized_config.metadata.vendor

    findings: List[Dict[str, Any]] = []

    for rule in COMPLIANCE_RULES:
        vendors = rule.get("vendors", [])

        if vendor not in vendors:
            continue

        result = _evaluate_rule(
            rule=rule,
            normalized_config=normalized_config,
        )

        if result["status"] not in VALID_STATUSES:
            raise ValueError(
                f"Invalid compliance status: {result['status']}"
            )

        findings.append(result)

    findings.sort(
        key=lambda finding: (
            SEVERITY_ORDER.get(
                str(finding["severity"]).lower(),
                99,
            ),
            finding["status"] != "FAIL",
            finding["id"],
        )
    )

    summary = _build_summary(findings)

    return {
        "vendor": vendor,
        "hostname": normalized_config.metadata.hostname,
        "rule_count": len(findings),
        "findings": findings,
        "summary": summary,
    }


def _evaluate_rule(
    rule: Dict[str, Any],
    normalized_config: NormalizedConfig,
) -> Dict[str, Any]:
    check_name = str(rule["check"])

    status, evidence = _run_check(
        check_name=check_name,
        normalized_config=normalized_config,
    )

    vendor = normalized_config.metadata.vendor

    remediation = rule.get("remediation", {})
    vendor_remediation = remediation.get(vendor)

    return {
        "id": rule["id"],
        "name": rule["name"],
        "status": status,
        "severity": rule["severity"],
        "cis_theme": rule["cis_theme"],
        "description": rule["description"],
        "expected": rule["expected"],
        "evidence": evidence,
        "remediation": vendor_remediation,
    }


def _run_check(
    check_name: str,
    normalized_config: NormalizedConfig,
):
    security = (
        normalized_config.vendor_data.get("security", {})
        if normalized_config.vendor_data
        else {}
    )

    if check_name == "hostname_configured":
        hostname = normalized_config.metadata.hostname

        if hostname:
            return (
                "PASS",
                f"Hostname configured as '{hostname}'.",
            )

        return (
            "FAIL",
            "No hostname was found in the configuration.",
        )

    if check_name == "ssh_enabled":
        value = security.get("ssh_enabled")

        if value is True:
            return (
                "PASS",
                "SSH is enabled for management access.",
            )

        if value is False:
            return (
                "FAIL",
                "SSH is explicitly disabled.",
            )

        return (
            "NOT_ASSESSED",
            "The configuration does not provide enough evidence "
            "to determine whether SSH is enabled.",
        )

    if check_name == "ssh_version_2":
        version = security.get("ssh_version")

        if version is None:
            return (
                "NOT_ASSESSED",
                "No SSH version setting was found.",
            )

        if str(version) == "2":
            return (
                "PASS",
                "SSH version 2 is explicitly configured.",
            )

        return (
            "FAIL",
            f"SSH version is configured as {version!r}, not version 2.",
        )

    if check_name == "telnet_disabled":
        value = security.get("telnet_enabled")

        if value is False:
            return (
                "PASS",
                "Telnet is explicitly disabled for remote management.",
            )

        if value is True:
            return (
                "FAIL",
                "Telnet is enabled for remote management.",
            )

        return (
            "NOT_ASSESSED",
            "The configuration does not explicitly establish the "
            "Telnet state.",
        )

    if check_name == "password_encryption":
        value = security.get("password_encryption_enabled")

        if value is True:
            return (
                "PASS",
                "service password-encryption is configured.",
            )

        return (
            "FAIL",
            "service password-encryption was not found in "
            "the configuration.",
        )

    if check_name == "enable_secret":
        value = security.get("enable_secret_configured")

        if value is True:
            return (
                "PASS",
                "An enable secret is configured.",
            )

        return (
            "FAIL",
            "An enable secret was not found in the configuration.",
        )

    if check_name == "local_user_secrets":
        user_count = security.get("local_user_count")
        all_users_secret = security.get(
            "all_local_users_use_secret"
        )

        if user_count is None:
            return (
                "NOT_ASSESSED",
                "No local user inventory was found.",
            )

        if user_count == 0:
            return (
                "NOT_ASSESSED",
                "No local users were found to assess.",
            )

        if all_users_secret is True:
            return (
                "PASS",
                f"All {user_count} detected local users use secrets.",
            )

        if all_users_secret is False:
            return (
                "FAIL",
                "At least one detected local user does not use "
                "a secret.",
            )

        return (
            "NOT_ASSESSED",
            "The local user credential format could not be fully "
            "determined.",
        )

    if check_name == "vty_exec_timeout":
        timeout = security.get("vty_exec_timeout_minutes")

        if timeout is None:
            return (
                "NOT_ASSESSED",
                "No VTY exec-timeout was found.",
            )

        if timeout <= 10:
            return (
                "PASS",
                f"VTY exec-timeout is {timeout} minutes.",
            )

        return (
            "FAIL",
            f"VTY exec-timeout is {timeout} minutes.",
        )

    if check_name == "vty_access_class":
        value = security.get("vty_access_class_configured")

        if value is True:
            return (
                "PASS",
                "A VTY access-class is configured.",
            )

        if value is False:
            return (
                "FAIL",
                "No VTY access-class is configured.",
            )

        return (
            "NOT_ASSESSED",
            "The configuration does not provide enough evidence "
            "to assess VTY source restriction.",
        )

    if check_name == "management_banner":
        value = security.get("management_banner_configured")

        if value is True:
            return (
                "PASS",
                "A management warning/banner is configured.",
            )

        if value is False:
            return (
                "FAIL",
                "No management warning/banner was detected.",
            )

        return (
            "NOT_ASSESSED",
            "Banner configuration could not be assessed.",
        )

    if check_name == "snmp_default_communities":
        value = security.get("snmp_default_communities")

        if value is False:
            return (
                "PASS",
                "Known default SNMP communities were not detected.",
            )

        if value is True:
            return (
                "FAIL",
                "A known default SNMP community was detected.",
            )

        return (
            "NOT_ASSESSED",
            "SNMP community configuration could not be assessed.",
        )

    if check_name == "cdp_disabled":
        value = security.get("cdp_enabled")

        if value is False:
            return (
                "PASS",
                "CDP is explicitly disabled.",
            )

        if value is True:
            return (
                "FAIL",
                "CDP is enabled.",
            )

        return (
            "NOT_ASSESSED",
            "The configuration does not explicitly establish "
            "the CDP state.",
        )

    if check_name == "bootp_disabled":
        value = security.get("bootp_enabled")

        if value is False:
            return (
                "PASS",
                "The BOOTP server is explicitly disabled.",
            )

        if value is True:
            return (
                "FAIL",
                "The BOOTP server is enabled.",
            )

        return (
            "NOT_ASSESSED",
            "The BOOTP server state could not be determined.",
        )

    if check_name == "pfsense_https_admin":
        value = security.get("web_management_https")

        if value is True:
            return (
                "PASS",
                "pfSense web administration is configured for HTTPS.",
            )

        if value is False:
            return (
                "FAIL",
                "pfSense web administration is not configured for HTTPS.",
            )

        return (
            "NOT_ASSESSED",
            "The exported configuration does not contain enough "
            "web administration protocol evidence.",
        )

    if check_name == "pfsense_session_timeout":
        timeout = security.get("session_timeout_minutes")

        if timeout is None:
            return (
                "NOT_ASSESSED",
                "No administrative session timeout was found.",
            )

        if timeout <= 10:
            return (
                "PASS",
                f"Administrative session timeout is {timeout} minutes.",
            )

        return (
            "FAIL",
            f"Administrative session timeout is {timeout} minutes.",
        )

    if check_name == "pfsense_any_destination":
        value = security.get("firewall_allow_any_destination")

        if value is False:
            return (
                "PASS",
                "No allow rule with Any destination was detected.",
            )

        if value is True:
            return (
                "FAIL",
                "At least one allow rule uses Any as its destination.",
            )

        return (
            "NOT_ASSESSED",
            "Destination scope could not be completely assessed.",
        )

    if check_name == "pfsense_any_source":
        value = security.get("firewall_allow_any_source")

        if value is False:
            return (
                "PASS",
                "No allow rule with Any source was detected.",
            )

        if value is True:
            return (
                "FAIL",
                "At least one allow rule uses Any as its source.",
            )

        return (
            "NOT_ASSESSED",
            "Source scope could not be completely assessed.",
        )

    if check_name == "pfsense_any_service":
        value = security.get("firewall_allow_any_service")

        if value is False:
            return (
                "PASS",
                "No allow rule with unrestricted service scope was detected.",
            )

        if value is True:
            return (
                "FAIL",
                "At least one allow rule permits unrestricted services.",
            )

        return (
            "NOT_ASSESSED",
            "Service scope could not be completely assessed.",
        )

    if check_name == "pfsense_firewall_logging":
        value = security.get("firewall_logging_all_enabled")

        if value is True:
            return (
                "PASS",
                "All assessable firewall rules have logging enabled.",
            )

        if value is False:
            return (
                "FAIL",
                "At least one assessable firewall rule lacks logging.",
            )

        return (
            "NOT_ASSESSED",
            "Firewall logging state is not present in the exported "
            "configuration.",
        )

    raise ValueError(
        f"Unknown compliance check: {check_name}"
    )


def _build_summary(
    findings: List[Dict[str, Any]],
) -> Dict[str, Any]:
    summary: Dict[str, Any] = {
        "PASS": 0,
        "FAIL": 0,
        "NOT_ASSESSED": 0,
    }

    for finding in findings:
        summary[finding["status"]] += 1

    assessed = (
        summary["PASS"]
        + summary["FAIL"]
    )

    if assessed == 0:
        posture_score = None
    else:
        posture_score = round(
            summary["PASS"] / assessed * 100,
            1,
        )

    summary["assessed"] = assessed
    summary["posture_score"] = posture_score

    return summary