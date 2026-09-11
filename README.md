# TrustGate

### Real-Time Trust and Integrity Layer for MCP

TrustGate is a security gateway that protects AI agents from untrusted or modified **Model Context Protocol (MCP)** servers.

It verifies server identity, fingerprints approved tools, detects tool mutations, scans for prompt injection, and sanitizes untrusted tool output.

## Key Features

* Server identity and typosquatting detection
* SHA-256 tool fingerprinting and pinning
* Tool mutation detection with diff generation
* Prompt-injection scanning
* Tool output sanitization
* Deterministic `ALLOW`, `HOLD`, and `BLOCK` decisions

## Process Flow

```text
MCP Server
    ↓
Identity Verification
    ↓
Tool Fingerprinting
    ↓
Mutation Detection
    ↓
Security Scanning
    ↓
Output Sanitization
    ↓
Policy Decision
    ↓
AI Agent
```

## Tech Stack

**Python 3.11+** · **MCP Python SDK** · **FastMCP** · **SQLite** · **RapidFuzz** · **SHA-256** · **OpenRouter** · **Rich**

## Project Structure

```text
TrustGate/
├── trustgate/
│   ├── proxy/
│   ├── security/
│   ├── mechanisms/
│   ├── storage/
│   ├── policy/
│   └── console/
├── servers/
├── tests/
├── PRD.md
├── TECH_STACK.md
├── DEMO_SCRIPT.md
└── README.md
```

## Installation

```bash
git clone https://github.com/VGSAIRAIMA/TrustGate_MEGATHON26_CYBER_PS2.git
cd TrustGate_MEGATHON26_CYBER_PS2

python3 -m venv venv
source venv/bin/activate
pip install mcp anthropic rapidfuzz rich
```

## Usage

```bash
python3 trustgate/main.py run --target "python3 servers/calculator.py"
```

## Demo

TrustGate demonstrates:

* Typosquatted server detection
* Trusted tool fingerprinting
* Malicious tool mutation detection
* Prompt-injection sanitization
* Safe handling of legitimate updates

## Security Scope

TrustGate secures the **MCP tool and data channel** between AI agents and MCP servers. It is not a replacement for server sandboxing or operating-system-level security.

## Project

Developed for **MEGATHON26 — Cyber PS2**.

**TrustGate — Verify before trust.**
