from pathlib import Path

from app.parsers.pfsense_parser import PfSenseParser


SAMPLE_PATH = (
    Path(__file__).resolve().parents[3]
    / "sample_configs"
    / "pfsense"
    / "basic_firewall.xml"
)


def test_pfsense_parser_normalizes_configuration():
    config_text = SAMPLE_PATH.read_text(
        encoding="utf-8"
    )

    normalized = PfSenseParser().parse(
        config_text
    )

    assert normalized.metadata.vendor == "pfsense"
    assert normalized.metadata.hostname == "EDGE-FIREWALL"
    assert normalized.metadata.version == "2.7.2"

    assert len(normalized.interfaces) == 2

    wan = normalized.interfaces[0]

    assert wan.name == "wan"
    assert wan.enabled is True
    assert "203.0.113.2/24" in wan.ipv4_addresses

    lan = normalized.interfaces[1]

    assert lan.name == "lan"
    assert lan.enabled is True
    assert "10.0.0.1/24" in lan.ipv4_addresses

    assert len(normalized.firewall_rules) == 1

    rule = normalized.firewall_rules[0]

    assert rule.action == "pass"
    assert rule.interface == "lan"
    assert rule.protocol == "tcp"
    assert rule.enabled is True


def test_pfsense_security_evidence_is_extracted():
    config = """
<pfsense>
    <version>2.7.2</version>

    <system>
        <hostname>SECURITY-FIREWALL</hostname>

        <webgui>
            <protocol>https</protocol>
            <timeout>5</timeout>
        </webgui>

        <ssh>
            <enabled>yes</enabled>
            <banner>Authorized users only</banner>
        </ssh>
    </system>

    <filter>
        <rule>
            <type>pass</type>
            <interface>lan</interface>
            <protocol>tcp</protocol>

            <source>
                <any>no</any>
                <address>10.0.0.0/24</address>
            </source>

            <destination>
                <any>no</any>
                <address>192.0.2.10</address>
                <port>443</port>
            </destination>

            <log>yes</log>
        </rule>
    </filter>
</pfsense>
"""

    normalized = PfSenseParser().parse(
        config
    )

    security = normalized.vendor_data["security"]

    assert security[
        "web_management_https"
    ] is True

    assert security[
        "session_timeout_minutes"
    ] == 5

    assert security[
        "ssh_enabled"
    ] is True

    assert security[
        "management_banner_configured"
    ] is True

    assert security[
        "firewall_allow_any_source"
    ] is False

    assert security[
        "firewall_allow_any_destination"
    ] is False

    assert security[
        "firewall_allow_any_service"
    ] is False

    assert security[
        "firewall_logging_all_enabled"
    ] is True