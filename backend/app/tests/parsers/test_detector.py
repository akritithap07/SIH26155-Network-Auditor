from app.parsers.detector import detect_vendor


def test_detect_cisco_ios():
    config = """
version 15.2
hostname EDGE-ROUTER

interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0

ip route 0.0.0.0 0.0.0.0 10.0.0.254

line vty 0 4
 transport input ssh
"""

    result = detect_vendor(config)

    assert result["vendor"] == "cisco_ios"
    assert result["confidence"] == "high"
    assert result["status"] == "detected"
    assert result["scores"]["cisco_ios"] > result["scores"]["pfsense"]


def test_detect_pfsense():
    config = """
<?xml version="1.0"?>
<pfsense>
    <system>
        <hostname>firewall</hostname>
    </system>

    <interfaces>
        <wan>
            <enable>yes</enable>
        </wan>
    </interfaces>

    <filter>
        <rule>
            <type>pass</type>
        </rule>
    </filter>
</pfsense>
"""

    result = detect_vendor(config)

    assert result["vendor"] == "pfsense"
    assert result["confidence"] == "high"
    assert result["status"] == "detected"
    assert result["scores"]["pfsense"] > result["scores"]["cisco_ios"]


def test_detect_unknown_vendor():
    config = """
device_name=CORE-01
security_mode=adaptive
policy_engine=enabled
custom_magic_protocol=secure
"""

    result = detect_vendor(config)

    assert result["vendor"] == "unknown"
    assert result["status"] == "unknown_vendor"


def test_empty_configuration():
    result = detect_vendor("")

    assert result["vendor"] == "unknown"
    assert result["status"] == "unknown_vendor"
    assert result["confidence"] == "low"