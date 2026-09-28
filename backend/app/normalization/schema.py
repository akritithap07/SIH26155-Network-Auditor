from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class ConfigMetadata(BaseModel):
    vendor: str
    config_format: str
    hostname: Optional[str] = None
    version: Optional[str] = None
    source_type: str = "single_file"


class UnrecognizedEntry(BaseModel):
    line_number: Optional[int] = None
    text: str
    context: Optional[str] = None
    evidence: Optional[str] = None


class NetworkInterface(BaseModel):
    name: str
    description: Optional[str] = None
    enabled: Optional[bool] = None
    ipv4_addresses: List[str] = Field(default_factory=list)
    ipv6_addresses: List[str] = Field(default_factory=list)


class Route(BaseModel):
    destination: str
    mask: Optional[str] = None
    next_hop: Optional[str] = None
    interface: Optional[str] = None
    raw_evidence: Optional[str] = None


class FirewallRule(BaseModel):
    sequence: Optional[int] = None
    name: Optional[str] = None
    action: str
    interface: Optional[str] = None
    direction: Optional[str] = None
    protocol: Optional[str] = None
    source: Optional[str] = None
    source_port: Optional[str] = None
    destination: Optional[str] = None
    destination_port: Optional[str] = None
    enabled: bool = True
    raw_evidence: Optional[str] = None


class ManagementSettings(BaseModel):
    ssh_enabled: Optional[bool] = None
    ssh_version: Optional[str] = None
    telnet_enabled: Optional[bool] = None
    password_encryption_enabled: Optional[bool] = None
    remote_access_lines: List[str] = Field(default_factory=list)


class NormalizedConfig(BaseModel):
    metadata: ConfigMetadata
    interfaces: List[NetworkInterface] = Field(default_factory=list)
    routes: List[Route] = Field(default_factory=list)
    firewall_rules: List[FirewallRule] = Field(default_factory=list)
    management: ManagementSettings = Field(
        default_factory=ManagementSettings
    )
    unrecognized_entries: List[UnrecognizedEntry] = Field(
        default_factory=list
    )
    parser_warnings: List[str] = Field(default_factory=list)
    vendor_data: Dict[str, object] = Field(default_factory=dict)