SIH26155 - Network Security Compliance Auditor

Architecture Document

1. System objective

The MVP automates security assessment of network-device configuration files while keeping compliance logic vendor-neutral and evidence-driven. A user uploads a single configuration file; the system detects the vendor, parses vendor-specific syntax into a common Pydantic model, extracts security evidence, evaluates applicable CIS-aligned control themes, and returns traceable findings with remediation guidance. Unsupported or incomplete input is not guessed.

2. High-level architecture

                         +----------------------+
                         |     React + Vite     |
                         | upload / audit UI    |
                         +----------+-----------+
                                    |
                              HTTP multipart
                                    v
                         +----------------------+
                         |      FastAPI API      |
                         | /upload /normalize    |
                         | /audit                |
                         +----------+-----------+
                                    |
                                    v
                         +----------------------+
                         |   Vendor Detection    |
                         | evidence + scores     |
                         +----------+-----------+
                                    |
                    +---------------+---------------+
                    |                               |
                    v                               v
          +------------------+             +------------------+
          |   Cisco IOS      |             |     pfSense      |
          | CLI + Regex      |             | Python XML       |
          +--------+---------+             +--------+---------+
                   |                                |
                   +---------------+----------------+
                                   v
                         +----------------------+
                         |   NormalizedConfig   |
                         | metadata, interfaces |
                         | routes, ACL/firewall |
                         | security evidence    |
                         | unknown entries      |
                         +----------+-----------+
                                    |
                                    v
                         +----------------------+
                         | Deterministic CIS    |
                         | Compliance Engine     |
                         +----------+-----------+
                                    |
                       +------------+------------+
                       |            |             |
                      PASS         FAIL      NOT_ASSESSED
                       |            |             |
                       +------------+-------------+
                                    v
                         Evidence / Severity /
                         Remediation / Summary

3. Core data flow

UPLOAD -> DETECT -> PARSE -> NORMALIZE -> ASSESS -> REPORT DATA

Ingestion and detection: file size/encoding are validated before processing. The deterministic detector scores known Cisco IOS and pfSense signals. Unknown or ambiguous input is returned without a fabricated vendor assignment.

Parsing and normalization: Cisco CLI syntax is parsed with Python regular expressions; pfSense XML is parsed with Python's XML facilities. Both produce a shared NormalizedConfig containing metadata, interfaces, routes, firewall rules, management/security evidence, parser warnings, and unrecognized entries.

Compliance: the engine evaluates only rules applicable to the detected vendor. A rule returns PASS when evidence satisfies the expected state, FAIL when evidence contradicts it or a required setting is absent where the rule requires it, and NOT_ASSESSED when the export lacks sufficient reliable evidence.

4. Deterministic compliance model

The MVP uses a JSON rule catalog containing 20 internally defined CIS-aligned control themes. Internal identifiers such as CIS-NET-01 through CIS-NET-20 are application rule IDs; they should not be presented as official CIS recommendation numbers without an explicit mapping.

Each finding carries the rule ID, name, status, severity, CIS-aligned theme, description, expected state, evidence, and vendor-specific remediation guidance. Remediation is advisory only; the MVP does not execute network commands.

5. Learning architecture

The AI layer is advisory and deliberately isolated from compliance decisions:

Unrecognized line
      |
      v
Sentence Transformer embedding
      |
      v
Top candidate mappings + similarity score
      |
      v
Human confirmation
      |
      v
SQLite confirmed mapping
      |
      v
Reuse on future matching input

The current implementation uses all-MiniLM-L6-v2. Similarity scores are ranking signals, not probabilities. Only an explicit human confirmation is persisted. The deterministic compliance engine remains the sole decision layer.

6. Security and failure behavior

Unknown vendors are not guessed.

Incomplete configuration exports do not receive fabricated evidence.

NOT_ASSESSED is used when reliable evidence is unavailable.

Remediation suggestions are not automatically executed.

Learned mappings require human confirmation.

Vendor parsing stays separate from compliance rules, reducing vendor-specific branching.

7. Technology and persistence

Layer

Technology

Frontend

React + Vite

API

FastAPI + Uvicorn

Data model

Pydantic

Cisco parser

Regex / CLI parsing

pfSense parser

Python XML parsing

Compliance

JSON rules + deterministic engine

Learning

Sentence Transformers (all-MiniLM-L6-v2)

Persistence

SQLite

Testing

Pytest

8. Scope and extension path

Current MVP: single-file Cisco IOS/pfSense audit, 20 CIS-aligned themes, evidence-based findings, remediation guidance, end-to-end /api/audit, and semantic learning foundation.

Next differentiator: Shadow Rule Detection for overlapping/ordered ACL and firewall rules.

Deferred: FortiGate, NIST implementation, bulk uploads, live SSH, automatic remediation execution, RBAC, chatbot, change-impact analysis, blockchain/tamper-evident ledger, continuous monitoring, and enterprise inventory management.

The architecture is intentionally modular: new parsers produce the same normalized model, while future frameworks can reuse the compliance pipeline without replacing the ingestion layer.