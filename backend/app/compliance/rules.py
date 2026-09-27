from typing import Dict, List


COMPLIANCE_RULES: List[Dict[str, object]] = [
    {
        "id": "CIS-NET-01",
        "name": "Hostname configured",
        "vendors": ["cisco_ios", "pfsense"],
        "check": "hostname_configured",
        "severity": "medium",
        "cis_theme": "Secure device identification",
        "description": (
            "The device should have an explicit hostname configured."
        ),
        "expected": "A non-empty hostname is configured.",
        "remediation": {
            "cisco_ios": "hostname <DEVICE_NAME>",
            "pfsense": (
                "Set System > General Setup > Hostname to a meaningful "
                "device name."
            ),
        },
    },
    {
        "id": "CIS-NET-02",
        "name": "SSH enabled for management",
        "vendors": ["cisco_ios"],
        "check": "ssh_enabled",
        "severity": "high",
        "cis_theme": "Secure remote device access",
        "description": (
            "Remote administrative access should use SSH rather than "
            "unencrypted management protocols."
        ),
        "expected": "SSH is enabled for administrative access.",
        "remediation": {
            "cisco_ios": "ip ssh version 2",
        },
    },
    {
        "id": "CIS-NET-03",
        "name": "SSH version 2 configured",
        "vendors": ["cisco_ios"],
        "check": "ssh_version_2",
        "severity": "high",
        "cis_theme": "Secure remote device access",
        "description": (
            "Cisco remote administration should use SSH version 2."
        ),
        "expected": "SSH version is configured as 2.",
        "remediation": {
            "cisco_ios": "ip ssh version 2",
        },
    },
    {
        "id": "CIS-NET-04",
        "name": "Telnet disabled for remote management",
        "vendors": ["cisco_ios"],
        "check": "telnet_disabled",
        "severity": "high",
        "cis_theme": "Eliminate plaintext management protocols",
        "description": (
            "Telnet should not be permitted for remote administrative "
            "access."
        ),
        "expected": "Telnet is not enabled on remote management lines.",
        "remediation": {
            "cisco_ios": "line vty 0 4\n transport input ssh",
        },
    },
    {
        "id": "CIS-NET-05",
        "name": "Password encryption enabled",
        "vendors": ["cisco_ios"],
        "check": "password_encryption",
        "severity": "high",
        "cis_theme": "Protect locally stored credentials",
        "description": (
            "Cisco password encryption should be explicitly enabled."
        ),
        "expected": "service password-encryption is configured.",
        "remediation": {
            "cisco_ios": "service password-encryption",
        },
    },
    {
        "id": "CIS-NET-06",
        "name": "Enable secret configured",
        "vendors": ["cisco_ios"],
        "check": "enable_secret",
        "severity": "high",
        "cis_theme": "Protect privileged access",
        "description": (
            "A protected enable secret should be configured."
        ),
        "expected": "enable secret is present.",
        "remediation": {
            "cisco_ios": "enable secret <STRONG_SECRET>",
        },
    },
    {
        "id": "CIS-NET-07",
        "name": "Local users use encrypted secrets",
        "vendors": ["cisco_ios"],
        "check": "local_user_secrets",
        "severity": "high",
        "cis_theme": "Protect local authentication credentials",
        "description": (
            "Local user accounts should use encrypted secret values."
        ),
        "expected": (
            "All detected local user accounts use a secret rather than "
            "a plaintext password."
        ),
        "remediation": {
            "cisco_ios": (
                "username <USERNAME> secret <STRONG_SECRET>"
            ),
        },
    },
    {
        "id": "CIS-NET-08",
        "name": "VTY session timeout is no more than 10 minutes",
        "vendors": ["cisco_ios"],
        "check": "vty_exec_timeout",
        "severity": "medium",
        "cis_theme": "Limit unattended management sessions",
        "description": (
            "Remote management sessions should have a bounded idle "
            "timeout."
        ),
        "expected": "VTY exec-timeout is configured to 10 minutes or less.",
        "remediation": {
            "cisco_ios": (
                "line vty 0 4\n exec-timeout 10 0"
            ),
        },
    },
    {
        "id": "CIS-NET-09",
        "name": "VTY management access is restricted",
        "vendors": ["cisco_ios"],
        "check": "vty_access_class",
        "severity": "high",
        "cis_theme": "Restrict administrative access sources",
        "description": (
            "Remote management access should be restricted to approved "
            "source addresses."
        ),
        "expected": "An access-class is configured on VTY lines.",
        "remediation": {
            "cisco_ios": (
                "line vty 0 4\n access-class <ACL_NUMBER> in"
            ),
        },
    },
    {
        "id": "CIS-NET-10",
        "name": "Management warning banner configured",
        "vendors": ["cisco_ios", "pfsense"],
        "check": "management_banner",
        "severity": "low",
        "cis_theme": "Administrative warning and accountability",
        "description": (
            "An administrative warning or MOTD banner should be "
            "configured where supported."
        ),
        "expected": "A management warning/banner is explicitly configured.",
        "remediation": {
            "cisco_ios": (
                "banner motd #Authorized access only. Activity is monitored.#"
            ),
            "pfsense": (
                "Configure the SSH warning banner in the pfSense "
                "administrative settings."
            ),
        },
    },
    {
        "id": "CIS-NET-11",
        "name": "Default SNMP communities are not used",
        "vendors": ["cisco_ios"],
        "check": "snmp_default_communities",
        "severity": "high",
        "cis_theme": "Harden SNMP management",
        "description": (
            "Known default SNMP community strings should not be used."
        ),
        "expected": (
            "Default public/private SNMP communities are absent."
        ),
        "remediation": {
            "cisco_ios": (
                "no snmp-server community public\n"
                "no snmp-server community private"
            ),
        },
    },
    {
        "id": "CIS-NET-12",
        "name": "CDP disabled",
        "vendors": ["cisco_ios"],
        "check": "cdp_disabled",
        "severity": "medium",
        "cis_theme": "Reduce unnecessary network discovery",
        "description": (
            "Cisco Discovery Protocol should be disabled when it is "
            "not required."
        ),
        "expected": "no cdp run is configured.",
        "remediation": {
            "cisco_ios": "no cdp run",
        },
    },
    {
        "id": "CIS-NET-13",
        "name": "BOOTP service disabled",
        "vendors": ["cisco_ios"],
        "check": "bootp_disabled",
        "severity": "medium",
        "cis_theme": "Disable unnecessary network services",
        "description": (
            "The BOOTP server should be disabled when not required."
        ),
        "expected": "no ip bootp server is configured.",
        "remediation": {
            "cisco_ios": "no ip bootp server",
        },
    },
    {
        "id": "CIS-NET-14",
        "name": "pfSense hostname configured",
        "vendors": ["pfsense"],
        "check": "hostname_configured",
        "severity": "medium",
        "cis_theme": "Secure device identification",
        "description": (
            "pfSense should have an explicit hostname configured."
        ),
        "expected": "A non-empty hostname is configured.",
        "remediation": {
            "pfsense": (
                "Set System > General Setup > Hostname."
            ),
        },
    },
    {
        "id": "CIS-NET-15",
        "name": "pfSense web administration uses HTTPS",
        "vendors": ["pfsense"],
        "check": "pfsense_https_admin",
        "severity": "high",
        "cis_theme": "Secure web administration",
        "description": (
            "Web-based administrative access should use HTTPS."
        ),
        "expected": "The pfSense web GUI protocol is HTTPS.",
        "remediation": {
            "pfsense": (
                "Set the web GUI protocol to HTTPS in "
                "System > Advanced > Admin Access."
            ),
        },
    },
    {
        "id": "CIS-NET-16",
        "name": "pfSense management session timeout is no more than 10 minutes",
        "vendors": ["pfsense"],
        "check": "pfsense_session_timeout",
        "severity": "medium",
        "cis_theme": "Limit unattended management sessions",
        "description": (
            "Administrative sessions should expire after a bounded "
            "period of inactivity."
        ),
        "expected": "Management session timeout is 10 minutes or less.",
        "remediation": {
            "pfsense": (
                "Set the administrative session timeout to 10 minutes "
                "or less."
            ),
        },
    },
    {
        "id": "CIS-NET-17",
        "name": "pfSense firewall rules do not allow any destination",
        "vendors": ["pfsense"],
        "check": "pfsense_any_destination",
        "severity": "high",
        "cis_theme": "Avoid overly broad firewall permissions",
        "description": (
            "Allow rules should not unnecessarily permit access to every "
            "destination."
        ),
        "expected": "No allow rule uses Any as its destination.",
        "remediation": {
            "pfsense": (
                "Remove or narrow the affected allow rule destination."
            ),
        },
    },
    {
        "id": "CIS-NET-18",
        "name": "pfSense firewall rules do not allow any source",
        "vendors": ["pfsense"],
        "check": "pfsense_any_source",
        "severity": "high",
        "cis_theme": "Avoid overly broad firewall permissions",
        "description": (
            "Allow rules should not unnecessarily permit traffic from "
            "every source."
        ),
        "expected": "No allow rule uses Any as its source.",
        "remediation": {
            "pfsense": (
                "Remove or narrow the affected allow rule source."
            ),
        },
    },
    {
        "id": "CIS-NET-19",
        "name": "pfSense firewall rules do not allow any service",
        "vendors": ["pfsense"],
        "check": "pfsense_any_service",
        "severity": "high",
        "cis_theme": "Restrict allowed services and ports",
        "description": (
            "Allow rules should define the services required by the "
            "policy rather than every service."
        ),
        "expected": "No allow rule leaves the service unrestricted.",
        "remediation": {
            "pfsense": (
                "Specify the required protocol and destination port/service "
                "for the affected allow rule."
            ),
        },
    },
    {
        "id": "CIS-NET-20",
        "name": "pfSense firewall logging is enabled",
        "vendors": ["pfsense"],
        "check": "pfsense_firewall_logging",
        "severity": "medium",
        "cis_theme": "Maintain auditable firewall events",
        "description": (
            "Applicable firewall rules should have logging enabled."
        ),
        "expected": "All assessable firewall rules have logging enabled.",
        "remediation": {
            "pfsense": (
                "Enable logging on firewall rules where auditing is "
                "required."
            ),
        },
    },
]