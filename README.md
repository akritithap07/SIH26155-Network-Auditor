SIH26155 - Network Security Compliance Auditor

AI-assisted. Vendor-agnostic. Evidence-driven.

Turn a raw network configuration file into a traceable security assessment - with deterministic compliance results, actionable remediation, and human-controlled learning.

   

Project at a glance

Item

Details

SIH Problem Statement

SIH26155 - Network Security Compliance Auditor

Theme

Blockchain & Cybersecurity

Category

Software

Team

TrailBlazers

Current vendors

Cisco IOS, pfSense

Compliance model

20 CIS-aligned control themes

Decision model

Deterministic - PASS, FAIL, NOT_ASSESSED

Learning model

Semantic similarity + human confirmation

Persistence

SQLite for confirmed mappings

Primary audit API

POST /api/audit

Why this project?

Network-device security audits are difficult because configurations are large, vendor-specific, and often reviewed manually. A single configuration can contain access rules, management settings, interfaces, routes, and other security-relevant controls spread across many lines.

This project automates the repeatable part of that workflow:

Upload -> Detect -> Parse -> Normalize -> Assess -> Explain -> Remediate

The design principle is simple: the auditor should never invent evidence just to produce a compliance answer. When a configuration export does not contain enough reliable information, the result is NOT_ASSESSED.

What the current MVP does

Accepts a single network configuration file.

Detects supported vendors using deterministic configuration signals.

Supports Cisco IOS and pfSense.

Refuses to guess unsupported or unknown vendors.

Parses vendor-specific syntax into a common Pydantic NormalizedConfig model.

Normalizes shared entities such as interfaces, routes, firewall rules, management settings, and security evidence.

Evaluates 20 internally defined CIS-aligned control themes.

Produces PASS / FAIL / NOT_ASSESSED findings.

Preserves evidence, expected state, severity, and remediation guidance.

Exposes an end-to-end POST /api/audit endpoint.

Uses Sentence Transformers (all-MiniLM-L6-v2) to suggest mappings for unrecognized configuration lines.

Requires human confirmation before a learned mapping is persisted.

Stores confirmed mappings in SQLite and reuses exact learned mappings later.

Provides a React + Vite upload and vendor-detection interface.

Important: The AI layer is advisory. It suggests mappings; it does not decide whether a control passes or fails.

Product architecture

                         +----------------------+
                         |     React + Vite     |
                         | Upload / Audit UI    |
                         +----------+-----------+
                                    |
                              HTTP multipart
                                    |
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
          | CLI / Regex      |             | Python XML       |
          +--------+---------+             +--------+---------+
                   |                                |
                   +---------------+----------------+
                                   |
                                   v
                         +----------------------+
                         |   NormalizedConfig   |
                         | shared vendor-neutral|
                         | security model       |
                         +----------+-----------+
                                    |
                                    v
                         +----------------------+
                         | Deterministic CIS    |
                         | Compliance Engine     |
                         +----------+-----------+
                                    |
                         +----------+-----------+
                         |          |            |
                        PASS       FAIL     NOT_ASSESSED
                         |          |            |
                         +----------+------------+
                                    |
                                    v
                         Evidence / Severity /
                         Remediation / Summary

 Advisory learning path:
 Unrecognized line -> embeddings -> top candidates -> human confirmation -> SQLite -> reuse

For a deeper system view, see docs/architecture.md. The printable two-page version is available at docs/architecture.pdf.

Key differentiators

1. Evidence-first compliance

The engine evaluates the evidence actually available in the configuration. It distinguishes a genuine failure from a configuration export that simply does not provide enough evidence.

2. Vendor-neutral compliance layer

Cisco IOS and pfSense are parsed differently, but both feed the same normalized concepts. This prevents the compliance logic from becoming a collection of vendor-specific branches.

3. Human-controlled semantic learning

When the parser encounters an unfamiliar line, the semantic mapper returns ranked candidates with similarity scores and confidence bands. A human explicitly confirms the mapping before it becomes learned knowledge.

4. Security-focused rule analysis

The architecture is prepared for the next differentiator: Shadow Rule Detection for overlapping and ordered ACL/firewall rules, where an earlier broad rule can make a later rule ineffective.

Technology stack

Layer

Technology

Frontend

React, Vite, JavaScript, CSS

Backend

FastAPI, Python, Uvicorn

Data validation

Pydantic

Cisco parsing

Python + regular expressions

pfSense parsing

Python XML parser

Compliance

JSON rule catalog + deterministic evaluator

Semantic learning

Sentence Transformers, all-MiniLM-L6-v2

Persistence

SQLite

Testing

Pytest

Repository structure

SIH26155-Network-Auditor/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   ├── analysis.py
│   │   │   ├── reports.py
│   │   │   ├── training.py
│   │   │   └── upload.py
│   │   ├── compliance/
│   │   │   ├── engine.py
│   │   │   └── rules.py
│   │   ├── learning/
│   │   │   ├── store.py
│   │   │   └── trainer.py
│   │   ├── normalization/
│   │   │   ├── normalizer.py
│   │   │   └── schema.py
│   │   ├── parsers/
│   │   │   ├── base.py
│   │   │   ├── cisco_parser.py
│   │   │   ├── detector.py
│   │   │   └── pfsense_parser.py
│   │   └── main.py
│   ├── data/
│   │   └── learning_examples.json
│   ├── tests/
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   └── services/
│   └── package.json
├── rules/
│   └── cis/
├── sample_configs/
│   ├── cisco/
│   ├── pfsense/
│   └── unknown/
├── docs/
│   ├── architecture.md
│   └── architecture.pdf
└── README.md

The exact repository contents should always be treated as the source of truth. The tree above describes the current intended structure.

Prerequisites

Recommended local setup:

Python 3.10+ with a working pip installation.

Node.js + npm.

Git for version control.

Internet access for the first download of the Sentence Transformers model.

The current development environment has been validated with Python 3.14 and sentence-transformers 6.1.0.

Setup - Windows

1. Clone the repository

git clone <YOUR_GITHUB_REPOSITORY_URL>
cd SIH26155-Network-Auditor

2. Create and activate a backend virtual environment

From the project root:

cd backend
python -m venv venv
venv\Scripts\activate

3. Install backend dependencies

python -m pip install --upgrade pip
pip install -r requirements.txt

4. Start the backend

uvicorn app.main:app --reload

Backend URLs:

Health: http://127.0.0.1:8000/health

Swagger: http://127.0.0.1:8000/docs

5. Start the frontend

Open a second terminal:

cd C:\Projects\SIH26155-Network-Auditor\frontend
npm install
npm run dev

Open the URL printed by Vite, normally:

http://localhost:5173

First-run model download

The semantic mapper uses:

all-MiniLM-L6-v2

The first real use may download model weights. Subsequent local runs reuse the downloaded model cache.

You can verify the installation with:

python -c "import sentence_transformers; print(sentence_transformers.__version__)"

and:

python -c "from sentence_transformers import SentenceTransformer; print('SentenceTransformer import: OK')"

Running the test suite

From backend:

pytest -q

Latest validated project checkpoint:

22 passed, 1 warning

The warning was a dependency deprecation warning from the test client stack; it did not cause a test failure.

The suite covers:

vendor detection

Cisco parsing

pfSense parsing

security evidence extraction

compliance engine behavior

audit API behavior

learning-store persistence

semantic mapping behavior

Using the application

Option A - Browser UI

Start the FastAPI backend.

Start the Vite frontend.

Open http://localhost:5173.

Select a configuration file.

Upload/analyze the file.

Review vendor detection and the returned audit information.

Option B - Swagger

Open:

http://127.0.0.1:8000/docs

Useful endpoints:

Method

Endpoint

Purpose

GET

/health

Service health check

POST

/api/upload

Upload + vendor detection

POST

/api/normalize

Parse into NormalizedConfig

POST

/api/audit

Complete detect -> parse -> normalize -> compliance flow

Use Try it out -> Choose File -> Execute in Swagger for file-upload endpoints.

Sample configurations

The repository contains small fixtures for repeatable demos and tests:

sample_configs/
├── cisco/
│   └── basic_router.conf
├── pfsense/
│   └── basic_firewall.xml
└── unknown/
    └── unknown.conf

Expected behavior:

Cisco sample -> cisco_ios

pfSense sample -> pfsense

Unknown sample -> unknown_vendor, with no fabricated normalization or compliance assessment

Compliance result model

Every applicable rule resolves to one of three states:

Status

Meaning

PASS

The available evidence satisfies the expected condition.

FAIL

The available evidence contradicts the expected condition or a required setting is missing where the rule defines absence as failure.

NOT_ASSESSED

The configuration export does not contain enough reliable evidence to decide.

Each finding can include:

rule ID
rule name
status
severity
CIS-aligned theme
description
expected state
evidence
remediation

The posture score, where present, is a sample/demo score derived from the assessed PASS/FAIL results. It is not an external certification score.

AI-assisted learning model

The learning layer is intentionally constrained:

Unrecognized configuration line
            |
            v
Semantic embedding
            |
            v
Top candidate mappings
            |
            v
Human confirmation
            |
            v
SQLite persistence
            |
            v
Future reuse

A similarity value is used as a ranking signal, not as a probability of correctness.

The AI layer never directly changes a compliance result.

Security and failure behavior

The system is intentionally fail-safe around incomplete information:

Unknown vendors are not guessed.

Unsupported vendors do not receive a fabricated vendor-specific assessment.

Missing configuration evidence is not invented.

NOT_ASSESSED is used where evidence is insufficient.

Remediation commands are recommendations only.

The current MVP does not automatically execute CLI changes.

Learned mappings require explicit human confirmation.

Semantic similarity is a candidate-ranking signal, not proof of correctness.

Current scope vs. deferred scope

Current MVP

Single-file configuration audit

Cisco IOS

pfSense

Vendor detection

Vendor-neutral normalization

20 CIS-aligned control themes

PASS / FAIL / NOT_ASSESSED

Evidence and remediation

End-to-end /api/audit

Semantic learning foundation

Human-confirmed mapping persistence

React/Vite upload flow

Deferred / future

FortiGate support

NIST implementation

Bulk uploads

Live SSH access

Automatic remediation execution

RBAC/authentication

Chatbot interface

Change-impact analysis

Blockchain / tamper-evident audit ledger

Continuous monitoring

Enterprise inventory management

Large-scale vendor coverage

Shadow Rule Detection as a fuller analysis module

The current MVP is deliberately smaller than a production enterprise platform. The architecture is modular so additional vendors, frameworks, and analysis modules can be added without rewriting the core compliance model.

Demo flow for evaluators

A strong end-to-end demo is:

1. Upload Cisco IOS config
2. Show vendor detection
3. Run /api/audit
4. Show PASS / FAIL / NOT_ASSESSED
5. Open one finding and trace it to configuration evidence
6. Show remediation guidance
7. Upload pfSense config
8. Show the same normalized/compliance pipeline handling a different format
9. Upload unknown.conf and show that the system refuses to guess
10. Demonstrate semantic mapping on an unfamiliar line
11. Confirm a candidate and show the learned mapping is persisted

Engineering principles

Deterministic core, AI-assisted edge. Security decisions are explicit and testable. The AI layer helps the system learn how to interpret new syntax without becoming the authority on whether a control passes.

Evidence over assumptions. A useful security auditor should be able to explain why it reached a result.

Vendor abstraction. Parsing is vendor-specific; compliance logic is not.

Incremental validation. Each major layer is covered by automated tests before the next layer is added.

Documentation

docs/architecture.md - concise system architecture and data flow

docs/architecture.pdf - printable two-page architecture document