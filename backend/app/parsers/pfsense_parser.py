import ipaddress
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional

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


class PfSenseParser(BaseConfigParser):
    vendor = "pfsense"
    config_format = "pfsense_xml"

    def parse(
        self,
        config_text: str,
    ) -> NormalizedConfig:
        if not isinstance(config_text, str):
            raise TypeError(
                "config_text must be a string"
            )

        try:
            root = ET.fromstring(config_text)
        except ET.ParseError as exc:
            raise ValueError(
                f"Invalid pfSense XML configuration: {exc}"
            ) from exc

        hostname = _find_text(
            root,
            "./system/hostname",
        )

        version = _find_text(
            root,
            "./version",
        )

        interfaces: List[NetworkInterface] = []
        routes: List[Route] = []
        firewall_rules: List[FirewallRule] = []
        unrecognized_entries: List[
            UnrecognizedEntry
        ] = []

        management = ManagementSettings()

        security: Dict[str, object] = {
            "ssh_enabled": None,
            "web_management_https": None,
            "session_timeout_minutes": None,
            "management_banner_configured": None,
            "firewall_allow_any_destination": None,
            "firewall_allow_any_source": None,
            "firewall_allow_any_service": None,
            "firewall_logging_all_enabled": None,
        }

        # -------------------------------------------------------------
        # Interfaces
        # -------------------------------------------------------------

        interfaces_node = root.find(
            "./interfaces"
        )

        if interfaces_node is not None:
            for interface_node in list(
                interfaces_node
            ):
                if not isinstance(
                    interface_node.tag,
                    str,
                ):
                    continue

                interface_name = interface_node.tag

                enabled_value = _find_text(
                    interface_node,
                    "./enable",
                )

                ip_address = _find_text(
                    interface_node,
                    "./ipaddr",
                )

                subnet = _find_text(
                    interface_node,
                    "./subnet",
                )

                normalized_ipv4: List[str] = []

                if (
                    ip_address
                    and _looks_like_ipv4(ip_address)
                ):
                    if (
                        subnet
                        and subnet.isdigit()
                    ):
                        normalized_ipv4.append(
                            f"{ip_address}/{subnet}"
                        )
                    else:
                        normalized_ipv4.append(
                            ip_address
                        )

                interfaces.append(
                    NetworkInterface(
                        name=interface_name,
                        enabled=_parse_bool(
                            enabled_value
                        ),
                        ipv4_addresses=normalized_ipv4,
                    )
                )

        # -------------------------------------------------------------
        # pfSense management settings
        # -------------------------------------------------------------

        webgui_protocol = _find_text(
            root,
            "./system/webgui/protocol",
        )

        if webgui_protocol:
            protocol = webgui_protocol.lower()

            if protocol == "https":
                security[
                    "web_management_https"
                ] = True

            elif protocol == "http":
                security[
                    "web_management_https"
                ] = False

        ssh_enabled = _find_first_bool(
            root,
            [
                "./system/ssh/enabled",
                "./system/ssh/enable",
            ],
        )

        if ssh_enabled is not None:
            security["ssh_enabled"] = ssh_enabled
            management.ssh_enabled = ssh_enabled

        session_timeout = _find_first_number(
            root,
            [
                "./system/webgui/timeout",
                "./system/webgui/session_timeout",
            ],
        )

        if session_timeout is not None:
            security[
                "session_timeout_minutes"
            ] = session_timeout

        banner = _first_text(
            root,
            [
                "./system/ssh/banner",
                "./system/webgui/banner",
            ],
        )

        if banner is not None:
            security[
                "management_banner_configured"
            ] = bool(
                banner.strip()
            )

        # -------------------------------------------------------------
        # Firewall rules
        # -------------------------------------------------------------

        filter_node = root.find(
            "./filter"
        )

        rule_nodes = []

        if filter_node is not None:
            rule_nodes = filter_node.findall(
                "./rule"
            )

        allow_any_source = False
        allow_any_destination = False
        allow_any_service = False

        logging_states: List[Optional[bool]] = []

        for sequence, rule_node in enumerate(
            rule_nodes,
            start=1,
        ):
            rule_type = _find_text(
                rule_node,
                "./type",
            )

            if not rule_type:
                continue

            action = rule_type.lower()

            source = _extract_endpoint(
                rule_node,
                "source",
            )

            destination = _extract_endpoint(
                rule_node,
                "destination",
            )

            source_port = _extract_port(
                rule_node,
                "source",
            )

            destination_port = _extract_port(
                rule_node,
                "destination",
            )

            protocol = _find_text(
                rule_node,
                "./protocol",
            )

            log_value = _find_text(
                rule_node,
                "./log",
            )

            log_state = _parse_bool(
                log_value
            )

            logging_states.append(
                log_state
            )

            if action in {
                "pass",
                "allow",
            }:
                if _is_explicit_any(
                    rule_node,
                    "source",
                ):
                    allow_any_source = True

                if _is_explicit_any(
                    rule_node,
                    "destination",
                ):
                    allow_any_destination = True

                if _service_is_unrestricted(
                    protocol=protocol,
                    destination_port=destination_port,
                ):
                    allow_any_service = True

            firewall_rules.append(
                FirewallRule(
                    sequence=sequence,
                    name=_find_text(
                        rule_node,
                        "./descr",
                    ),
                    action=action,
                    interface=_find_text(
                        rule_node,
                        "./interface",
                    ),
                    direction=_find_text(
                        rule_node,
                        "./direction",
                    ),
                    protocol=protocol,
                    source=source,
                    source_port=source_port,
                    destination=destination,
                    destination_port=destination_port,
                    enabled=not (
                        _parse_bool(
                            _find_text(
                                rule_node,
                                "./disabled",
                            )
                        )
                        is True
                    ),
                    raw_evidence=ET.tostring(
                        rule_node,
                        encoding="unicode",
                    ),
                )
            )

        if rule_nodes:
            security[
                "firewall_allow_any_source"
            ] = allow_any_source

            security[
                "firewall_allow_any_destination"
            ] = allow_any_destination

            security[
                "firewall_allow_any_service"
            ] = allow_any_service

            if logging_states and all(
                state is True
                for state in logging_states
            ):
                security[
                    "firewall_logging_all_enabled"
                ] = True

            elif any(
                state is False
                for state in logging_states
            ):
                security[
                    "firewall_logging_all_enabled"
                ] = False

            else:
                security[
                    "firewall_logging_all_enabled"
                ] = None

        return NormalizedConfig(
            metadata=ConfigMetadata(
                vendor=self.vendor,
                config_format=self.config_format,
                hostname=hostname,
                version=version,
            ),
            interfaces=interfaces,
            routes=routes,
            firewall_rules=firewall_rules,
            management=management,
            unrecognized_entries=unrecognized_entries,
            vendor_data={
                "security": security,
            },
        )


def _find_text(
    root: ET.Element,
    path: str,
) -> Optional[str]:
    node = root.find(path)

    if node is None:
        return None

    if node.text is None:
        return None

    value = node.text.strip()

    return value if value else None


def _first_text(
    root: ET.Element,
    paths: List[str],
) -> Optional[str]:
    for path in paths:
        value = _find_text(
            root,
            path,
        )

        if value is not None:
            return value

    return None


def _find_first_bool(
    root: ET.Element,
    paths: List[str],
) -> Optional[bool]:
    for path in paths:
        value = _parse_bool(
            _find_text(root, path)
        )

        if value is not None:
            return value

    return None


def _find_first_number(
    root: ET.Element,
    paths: List[str],
) -> Optional[float]:
    for path in paths:
        value = _find_text(root, path)

        if value is None:
            continue

        try:
            return float(value)
        except ValueError:
            continue

    return None


def _parse_bool(
    value: Optional[str],
) -> Optional[bool]:
    if value is None:
        return None

    normalized = value.strip().lower()

    if normalized in {
        "yes",
        "true",
        "1",
        "on",
        "enabled",
    }:
        return True

    if normalized in {
        "no",
        "false",
        "0",
        "off",
        "disabled",
    }:
        return False

    return None


def _looks_like_ipv4(
    value: str,
) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def _is_explicit_any(
    rule_node: ET.Element,
    section_name: str,
) -> bool:
    section = rule_node.find(
        f"./{section_name}"
    )

    if section is None:
        return False

    any_value = _find_text(
        section,
        "./any",
    )

    return (
        any_value is not None
        and any_value.lower()
        in {"yes", "true", "1"}
    )


def _extract_endpoint(
    rule_node: ET.Element,
    section_name: str,
) -> Optional[str]:
    section = rule_node.find(
        f"./{section_name}"
    )

    if section is None:
        return None

    if _is_explicit_any(
        rule_node,
        section_name,
    ):
        return "0.0.0.0/0"

    address = _find_text(
        section,
        "./address",
    )

    if address:
        return address

    network = _find_text(
        section,
        "./network",
    )

    if network:
        return network

    return None


def _extract_port(
    rule_node: ET.Element,
    section_name: str,
) -> Optional[str]:
    section = rule_node.find(
        f"./{section_name}"
    )

    if section is None:
        return None

    port = _find_text(
        section,
        "./port",
    )

    if port:
        return port

    return None


def _service_is_unrestricted(
    protocol: Optional[str],
    destination_port: Optional[str],
) -> bool:
    normalized_protocol = (
        protocol.strip().lower()
        if protocol
        else None
    )

    if normalized_protocol in {
        None,
        "",
        "any",
        "ip",
    }:
        return True

    if normalized_protocol in {
        "tcp",
        "udp",
        "tcp/udp",
    } and not destination_port:
        return True

    return False