from app.compliance.engine import run_compliance
from app.parsers.cisco_parser import CiscoIOSParser
from app.parsers.pfsense_parser import PfSenseParser


def test_cisco_compliance_engine_returns_statuses():
    config = """
version 15.2
hostname TEST-ROUTER
service password-encryption
enable secret 9 hash
ip ssh version 2
no cdp run
no ip bootp server
banner motd #Authorized only#

line vty 0 4
 transport input ssh
 exec-timeout 5 0
 access-class 10 in
"""

    normalized = CiscoIOSParser().parse(config)

    result = run_compliance(normalized)

    assert result["vendor"] == "cisco_ios"
    assert result["rule_count"] == 13

    statuses = {
        finding["status"]
        for finding in result["findings"]
    }

    assert "PASS" in statuses
    assert "NOT_ASSESSED" in statuses


def test_cisco_telnet_failure_is_deterministic():
    config = """
version 15.2
hostname TEST-ROUTER

line vty 0 4
 transport input telnet
"""

    normalized = CiscoIOSParser().parse(config)

    result = run_compliance(normalized)

    telnet_finding = next(
        finding
        for finding in result["findings"]
        if finding["id"] == "CIS-NET-04"
    )

    assert telnet_finding["status"] == "FAIL"
    assert "Telnet is enabled" in (
        telnet_finding["evidence"]
    )


def test_missing_ssh_version_is_not_assessed():
    config = """
version 15.2
hostname TEST-ROUTER

line vty 0 4
 transport input ssh
"""

    normalized = CiscoIOSParser().parse(config)

    result = run_compliance(normalized)

    ssh_version_finding = next(
        finding
        for finding in result["findings"]
        if finding["id"] == "CIS-NET-03"
    )

    assert (
        ssh_version_finding["status"]
        == "NOT_ASSESSED"
    )


def test_pfsense_compliance_engine_returns_statuses():
    config = """
<pfsense>
    <version>2.7.2</version>

    <system>
        <hostname>TEST-FIREWALL</hostname>

        <webgui>
            <protocol>https</protocol>
            <timeout>5</timeout>
        </webgui>
    </system>

    <filter>
        <rule>
            <type>pass</type>
            <interface>lan</interface>
            <protocol>tcp</protocol>
            <source>
                <any>yes</any>
            </source>
            <destination>
                <any>no</any>
                <address>192.0.2.10</address>
            </destination>
            <destination>
                <any>no</any>
                <address>192.0.2.10</address>
                <port>443</port>
            </destination>
            <log>no</log>
        </rule>
    </filter>
</pfsense>
"""

    normalized = PfSenseParser().parse(config)

    result = run_compliance(normalized)

    assert result["vendor"] == "pfsense"
    assert result["rule_count"] == 9

    source_finding = next(
        finding
        for finding in result["findings"]
        if finding["id"] == "CIS-NET-18"
    )

    logging_finding = next(
        finding
        for finding in result["findings"]
        if finding["id"] == "CIS-NET-20"
    )

    assert source_finding["status"] == "FAIL"
    assert logging_finding["status"] == "FAIL"