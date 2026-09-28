from app.parsers.pfsense_parser import PfSenseParser


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

    normalized = PfSenseParser().parse(config)

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