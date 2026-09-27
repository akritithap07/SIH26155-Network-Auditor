import ipaddress
import re
from typing import Dict, List, Optional, Tuple

from app.normalization.schema import (
    ConfigMetadata,
    FirewallRule,
    ManagementSettings,
    NetworkInterface,
    NormalizedConfig,
    Route,
    UnrecognizedEntry,
)
from app.parsers.base import BaseConfigParser


class CiscoIOSParser(BaseConfigParser):
    vendor = "cisco_ios"
    config_format = "cisco_ios_cli"

    def parse(self, config_text: str) -> NormalizedConfig:
        if not isinstance(config_text, str):
            raise TypeError("config_text must be a string")

        lines = (
            config_text
            .replace("\r\n", "\n")
            .replace("\r", "\n")
            .splitlines()
        )

        hostname: Optional[str] = None
        version: Optional[str] = None

        interfaces: List[NetworkInterface] = []
        routes: List[Route] = []
        firewall_rules: List[FirewallRule] = []
        unrecognized_entries: List[UnrecognizedEntry] = []

        management = ManagementSettings()

        security: Dict[str, object] = {
            "ssh_enabled": None,
            "ssh_version": None,
            "telnet_enabled": None,
            "password_encryption_enabled": False,
            "enable_secret_configured": False,
            "local_user_count": 0,
            "all_local_users_use_secret": None,
            "vty_exec_timeout_minutes": None,
            "vty_access_class_configured": None,
            "management_banner_configured": False,
            "snmp_default_communities": False,
            "cdp_enabled": None,
            "bootp_enabled": None,
        }

        local_users: Dict[str, str] = {}
        vty_blocks: List[Dict[str, object]] = []

        current_interface: Optional[NetworkInterface] = None
        current_acl_name: Optional[str] = None
        current_vty: Optional[Dict[str, object]] = None

        for line_number, original_line in enumerate(
            lines,
            start=1,
        ):
            stripped = original_line.strip()

            if not stripped or stripped == "!":
                continue

            if stripped.lower() == "end":
                continue

            # ---------------------------------------------------------
            # Global configuration
            # ---------------------------------------------------------

            version_match = re.match(
                r"^version\s+(.+)$",
                stripped,
                re.IGNORECASE,
            )
            if version_match:
                version = version_match.group(1).strip()
                continue

            hostname_match = re.match(
                r"^hostname\s+(\S+)$",
                stripped,
                re.IGNORECASE,
            )
            if hostname_match:
                hostname = hostname_match.group(1)
                continue

            interface_match = re.match(
                r"^interface\s+(.+)$",
                stripped,
                re.IGNORECASE,
            )
            if interface_match:
                if current_interface is not None:
                    interfaces.append(current_interface)

                current_interface = NetworkInterface(
                    name=interface_match.group(1).strip(),
                    enabled=True,
                )

                current_acl_name = None
                current_vty = None
                continue

            vty_match = re.match(
                r"^line\s+vty\s+(.+)$",
                stripped,
                re.IGNORECASE,
            )
            if vty_match:
                if current_interface is not None:
                    interfaces.append(current_interface)
                    current_interface = None

                current_acl_name = None

                current_vty = {
                    "range": vty_match.group(1).strip(),
                    "ssh_enabled": None,
                    "telnet_enabled": None,
                    "exec_timeout_minutes": None,
                    "access_class_configured": None,
                }

                vty_blocks.append(current_vty)

                management.remote_access_lines.append(
                    f"line vty {current_vty['range']}"
                )

                continue

            acl_context_match = re.match(
                r"^ip\s+access-list\s+(standard|extended)\s+(.+)$",
                stripped,
                re.IGNORECASE,
            )
            if acl_context_match:
                if current_interface is not None:
                    interfaces.append(current_interface)
                    current_interface = None

                current_vty = None
                current_acl_name = acl_context_match.group(2).strip()

                continue

            # ---------------------------------------------------------
            # Interface subcommands
            # ---------------------------------------------------------

            if current_interface is not None:
                description_match = re.match(
                    r"^description\s+(.+)$",
                    stripped,
                    re.IGNORECASE,
                )

                if description_match:
                    current_interface.description = (
                        description_match.group(1).strip()
                    )
                    continue

                ip_address_match = re.match(
                    r"^ip\s+address\s+(\S+)\s+(\S+)$",
                    stripped,
                    re.IGNORECASE,
                )

                if ip_address_match:
                    ip_address = ip_address_match.group(1)
                    subnet = ip_address_match.group(2)

                    normalized_address = _normalize_ipv4_address(
                        ip_address,
                        subnet,
                    )

                    current_interface.ipv4_addresses.append(
                        normalized_address
                    )

                    continue

                ipv6_match = re.match(
                    r"^ipv6\s+address\s+(.+)$",
                    stripped,
                    re.IGNORECASE,
                )

                if ipv6_match:
                    current_interface.ipv6_addresses.append(
                        ipv6_match.group(1).strip()
                    )
                    continue

                if stripped.lower() == "shutdown":
                    current_interface.enabled = False
                    continue

                if stripped.lower() == "no shutdown":
                    current_interface.enabled = True
                    continue

            # ---------------------------------------------------------
            # VTY subcommands
            # ---------------------------------------------------------

            if current_vty is not None:
                transport_match = re.match(
                    r"^transport\s+input\s+(.+)$",
                    stripped,
                    re.IGNORECASE,
                )

                if transport_match:
                    protocols = set(
                        transport_match.group(1)
                        .lower()
                        .split()
                    )

                    if "none" in protocols:
                        current_vty["ssh_enabled"] = False
                        current_vty["telnet_enabled"] = False

                    elif "all" in protocols:
                        current_vty["ssh_enabled"] = True
                        current_vty["telnet_enabled"] = True

                    else:
                        current_vty["ssh_enabled"] = (
                            "ssh" in protocols
                        )
                        current_vty["telnet_enabled"] = (
                            "telnet" in protocols
                        )

                    continue

                timeout_match = re.match(
                    r"^exec-timeout\s+(\d+)(?:\s+(\d+))?$",
                    stripped,
                    re.IGNORECASE,
                )

                if timeout_match:
                    minutes = int(timeout_match.group(1))
                    seconds = int(
                        timeout_match.group(2) or 0
                    )

                    total_minutes = minutes + (
                        seconds / 60.0
                    )

                    current_vty["exec_timeout_minutes"] = (
                        total_minutes
                    )

                    continue

                access_class_match = re.match(
                    r"^access-class\s+\S+\s+(in|out)$",
                    stripped,
                    re.IGNORECASE,
                )

                if access_class_match:
                    current_vty[
                        "access_class_configured"
                    ] = True
                    continue

            # ---------------------------------------------------------
            # Named ACL entries
            # ---------------------------------------------------------

            if current_acl_name is not None:
                if re.match(r"^\d+\s+", stripped):
                    sequence_match = re.match(
                        r"^(\d+)\s+(.+)$",
                        stripped,
                    )

                    if sequence_match:
                        sequence = int(
                            sequence_match.group(1)
                        )

                        rule_body = sequence_match.group(2)

                        rule = _parse_cisco_acl_rule(
                            rule_body=rule_body,
                            raw_evidence=original_line,
                            sequence=sequence,
                            name=current_acl_name,
                        )

                        if rule is not None:
                            firewall_rules.append(rule)
                            continue

            # ---------------------------------------------------------
            # Numbered ACL
            # ---------------------------------------------------------

            numbered_acl_match = re.match(
                r"^access-list\s+(\d+)\s+(.+)$",
                stripped,
                re.IGNORECASE,
            )

            if numbered_acl_match:
                acl_number = numbered_acl_match.group(1)
                rule_body = numbered_acl_match.group(2)

                rule = _parse_cisco_acl_rule(
                    rule_body=rule_body,
                    raw_evidence=original_line,
                    sequence=None,
                    name=f"ACL {acl_number}",
                )

                if rule is not None:
                    firewall_rules.append(rule)
                    continue

            # ---------------------------------------------------------
            # SSH / management security settings
            # ---------------------------------------------------------

            ssh_version_match = re.match(
                r"^ip\s+ssh\s+version\s+(\S+)$",
                stripped,
                re.IGNORECASE,
            )

            if ssh_version_match:
                security["ssh_enabled"] = True
                security["ssh_version"] = (
                    ssh_version_match.group(1)
                )
                continue

            if re.match(
                r"^service\s+password-encryption$",
                stripped,
                re.IGNORECASE,
            ):
                security["password_encryption_enabled"] = True
                continue

            if re.match(
                r"^enable\s+secret\b",
                stripped,
                re.IGNORECASE,
            ):
                security["enable_secret_configured"] = True
                continue

            username_secret_match = re.match(
                r"^username\s+(\S+)\s+.*\bsecret\b",
                stripped,
                re.IGNORECASE,
            )

            if username_secret_match:
                username = username_secret_match.group(1)

                local_users[username] = "secret"

                continue

            username_password_match = re.match(
                r"^username\s+(\S+)\s+.*\bpassword\b",
                stripped,
                re.IGNORECASE,
            )

            if username_password_match:
                username = username_password_match.group(1)

                local_users[username] = "password"

                continue

            if re.match(
                r"^banner\s+(motd|login|exec)\b",
                stripped,
                re.IGNORECASE,
            ):
                security["management_banner_configured"] = True
                continue

            snmp_match = re.match(
                r"^snmp-server\s+community\s+(public|private)\b",
                stripped,
                re.IGNORECASE,
            )

            if snmp_match:
                security["snmp_default_communities"] = True
                continue

            if re.match(
                r"^no\s+snmp-server\s+community\s+(public|private)\b",
                stripped,
                re.IGNORECASE,
            ):
                continue

            if re.match(
                r"^no\s+cdp\s+run$",
                stripped,
                re.IGNORECASE,
            ):
                security["cdp_enabled"] = False
                continue

            if re.match(
                r"^cdp\s+run$",
                stripped,
                re.IGNORECASE,
            ):
                security["cdp_enabled"] = True
                continue

            if re.match(
                r"^no\s+ip\s+bootp\s+server$",
                stripped,
                re.IGNORECASE,
            ):
                security["bootp_enabled"] = False
                continue

            if re.match(
                r"^ip\s+bootp\s+server$",
                stripped,
                re.IGNORECASE,
            ):
                security["bootp_enabled"] = True
                continue

            # ---------------------------------------------------------
            # Static routes
            # ---------------------------------------------------------

            route_match = re.match(
                r"^ip\s+route\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(\S+))?",
                stripped,
                re.IGNORECASE,
            )

            if route_match:
                destination = route_match.group(1)
                mask = route_match.group(2)
                next_hop_or_interface = (
                    route_match.group(3)
                )
                optional_interface = route_match.group(4)

                next_hop = None
                interface = None

                if _looks_like_ip(
                    next_hop_or_interface
                ):
                    next_hop = next_hop_or_interface
                else:
                    interface = next_hop_or_interface

                if optional_interface:
                    interface = optional_interface

                routes.append(
                    Route(
                        destination=destination,
                        mask=mask,
                        next_hop=next_hop,
                        interface=interface,
                        raw_evidence=original_line,
                    )
                )

                continue

            # ---------------------------------------------------------
            # Anything else remains evidence for future learning
            # ---------------------------------------------------------

            unrecognized_entries.append(
                UnrecognizedEntry(
                    line_number=line_number,
                    text=original_line,
                    context=_detect_context(
                        current_interface,
                        current_vty,
                        current_acl_name,
                    ),
                )
            )

        if current_interface is not None:
            interfaces.append(current_interface)

        # -------------------------------------------------------------
        # Aggregate VTY evidence
        # -------------------------------------------------------------

        if vty_blocks:
            ssh_values = [
                block["ssh_enabled"]
                for block in vty_blocks
            ]

            telnet_values = [
                block["telnet_enabled"]
                for block in vty_blocks
            ]

            timeout_values = [
                block["exec_timeout_minutes"]
                for block in vty_blocks
            ]

            access_values = [
                block["access_class_configured"]
                for block in vty_blocks
            ]

            explicit_ssh = [
                value for value in ssh_values
                if value is not None
            ]

            explicit_telnet = [
                value for value in telnet_values
                if value is not None
            ]

            explicit_timeouts = [
                value for value in timeout_values
                if value is not None
            ]

            explicit_access = [
                value for value in access_values
                if value is not None
            ]

            if explicit_ssh:
                security["ssh_enabled"] = any(
                    explicit_ssh
                )

            if explicit_telnet:
                security["telnet_enabled"] = any(
                    explicit_telnet
                )

            if len(explicit_timeouts) == len(
                vty_blocks
            ):
                security[
                    "vty_exec_timeout_minutes"
                ] = max(explicit_timeouts)

            if len(explicit_access) == len(
                vty_blocks
            ):
                security[
                    "vty_access_class_configured"
                ] = all(explicit_access)
            elif vty_blocks:
                security[
                    "vty_access_class_configured"
                ] = False

        # -------------------------------------------------------------
        # Aggregate local-user evidence
        # -------------------------------------------------------------

        security["local_user_count"] = len(local_users)

        if local_users:
            security[
                "all_local_users_use_secret"
            ] = all(
                auth_type == "secret"
                for auth_type in local_users.values()
            )

        metadata = ConfigMetadata(
            vendor=self.vendor,
            config_format=self.config_format,
            hostname=hostname,
            version=version,
        )

        return NormalizedConfig(
            metadata=metadata,
            interfaces=interfaces,
            routes=routes,
            firewall_rules=firewall_rules,
            management=management,
            unrecognized_entries=unrecognized_entries,
            vendor_data={
                "security": security,
            },
        )


def _parse_cisco_acl_rule(
    rule_body: str,
    raw_evidence: str,
    sequence: Optional[int],
    name: Optional[str],
) -> Optional[FirewallRule]:
    tokens = rule_body.split()

    if len(tokens) < 3:
        return None

    action = tokens[0].lower()
    protocol = tokens[1].lower()

    if action not in {"permit", "deny"}:
        return None

    index = 2

    source, index = _parse_cisco_address(
        tokens,
        index,
    )

    if source is None:
        return None

    source_port: Optional[str] = None

    if index < len(tokens):
        source_port_value, new_index = (
            _parse_port_expression(tokens, index)
        )

        if source_port_value is not None:
            source_port = source_port_value
            index = new_index

    destination, index = _parse_cisco_address(
        tokens,
        index,
    )

    if destination is None:
        return None

    destination_port: Optional[str] = None

    if index < len(tokens):
        destination_port_value, new_index = (
            _parse_port_expression(tokens, index)
        )

        if destination_port_value is not None:
            destination_port = destination_port_value

    return FirewallRule(
        sequence=sequence,
        name=name,
        action=action,
        protocol=protocol,
        source=source,
        source_port=source_port,
        destination=destination,
        destination_port=destination_port,
        raw_evidence=raw_evidence,
    )


def _parse_cisco_address(
    tokens: List[str],
    index: int,
) -> Tuple[Optional[str], int]:
    if index >= len(tokens):
        return None, index

    token = tokens[index].lower()

    if token == "any":
        return "0.0.0.0/0", index + 1

    if token == "host":
        if index + 1 >= len(tokens):
            return None, index

        host = tokens[index + 1]

        if _looks_like_ip(host):
            return f"{host}/32", index + 2

        return host, index + 2

    if _looks_like_ip(token):
        if (
            index + 1 < len(tokens)
            and _looks_like_wildcard(
                tokens[index + 1]
            )
        ):
            network = token
            wildcard = tokens[index + 1]

            cidr = _wildcard_to_cidr(
                network,
                wildcard,
            )

            return cidr, index + 2

        return token, index + 1

    return token, index + 1


def _parse_port_expression(
    tokens: List[str],
    index: int,
) -> Tuple[Optional[str], int]:
    if index >= len(tokens):
        return None, index

    operator = tokens[index].lower()

    if operator in {"eq", "gt", "lt", "neq"}:
        if index + 1 >= len(tokens):
            return None, index

        return (
            f"{operator} {tokens[index + 1]}",
            index + 2,
        )

    if operator == "range":
        if index + 2 >= len(tokens):
            return None, index

        return (
            f"range {tokens[index + 1]} "
            f"{tokens[index + 2]}",
            index + 3,
        )

    return None, index


def _normalize_ipv4_address(
    address: str,
    mask: str,
) -> str:
    try:
        network = ipaddress.IPv4Network(
            f"{address}/{mask}",
            strict=False,
        )

        return f"{address}/{network.prefixlen}"

    except ValueError:
        return f"{address}/{mask}"


def _wildcard_to_cidr(
    network: str,
    wildcard: str,
) -> str:
    try:
        wildcard_ip = ipaddress.IPv4Address(
            wildcard
        )

        subnet_mask_int = (
            int(wildcard_ip) ^ 0xFFFFFFFF
        )

        subnet_mask = ipaddress.IPv4Address(
            subnet_mask_int
        )

        prefix_length = ipaddress.IPv4Network(
            f"0.0.0.0/{subnet_mask}"
        ).prefixlen

        return f"{network}/{prefix_length}"

    except ValueError:
        return f"{network}/{wildcard}"


def _looks_like_ip(
    value: str,
) -> bool:
    try:
        ipaddress.ip_address(value)
        return True

    except ValueError:
        return False


def _looks_like_wildcard(
    value: str,
) -> bool:
    parts = value.split(".")

    if len(parts) != 4:
        return False

    try:
        return all(
            0 <= int(part) <= 255
            for part in parts
        )

    except ValueError:
        return False


def _detect_context(
    current_interface: Optional[NetworkInterface],
    current_vty: Optional[Dict[str, object]],
    current_acl_name: Optional[str],
) -> Optional[str]:
    if current_interface is not None:
        return (
            f"interface {current_interface.name}"
        )

    if current_vty is not None:
        return (
            f"line vty "
            f"{current_vty['range']}"
        )

    if current_acl_name is not None:
        return (
            f"ip access-list "
            f"{current_acl_name}"
        )

    return "global"