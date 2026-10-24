# SentinelEye

[![CI](https://github.com/janderik/sentinel-eye/actions/workflows/ci.yml/badge.svg)](https://github.com/janderik/sentinel-eye/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green)](https://fastapi.tiangolo.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Docker](https://img.shields.io/badge/docker-ready-blue)](https://docker.com)

**SentinelEye** is a production-grade Security Information and Event Management (SIEM) and Host-based Intrusion Detection System (HIDS). It collects, correlates, and analyzes security events in real-time, providing actionable alerts through a modern REST API.

```
                              ┌─────────────────────────────┐
                              │      DATA COLLECTORS        │
                              │  ┌─────────┐ ┌───────────┐  │
                              │  │  Syslog │ │   Windows  │  │
                              │  │ (UDP/TCP)│ │   Events   │  │
                              │  └────┬────┘ └─────┬─────┘  │
                              │       │            │        │
                              └───────┼────────────┼────────┘
                                      │            │
                                      ▼            ▼
                              ┌─────────────────────────────┐
                              │      EVENT PIPELINE          │
                              │  ┌──────────┐ ┌───────────┐  │
                              │  │  Rules   │ │Correlation│  │
                              │  │  Engine  │ │  Engine    │  │
                              │  └────┬─────┘ └─────┬─────┘  │
                              │       │              │       │
                              └───────┼──────────────┼───────┘
                                      │              │
                                      ▼              ▼
                              ┌─────────────────────────────┐
                              │         STORAGE             │
                              │  ┌──────────────────────┐   │
                              │  │   SQLite / PostgreSQL│   │
                              │  │  (events, alerts,    │   │
                              │  │   rules)             │   │
                              │  └──────────────────────┘   │
                              └───────────┬─────────────────┘
                                          │
                                          ▼
                              ┌─────────────────────────────┐
                              │     REST API (FastAPI)       │
                              │  ┌──────────────────────┐   │
                              │  │  /events  /alerts    │   │
                              │  │  /rules   /stats     │   │
                              │  │  /health             │   │
                              │  └──────────────────────┘   │
                              └─────────────────────────────┘
```

## Features

- **Real-time Event Collection** — Syslog (UDP/TCP, RFC 3164) and Windows Event Log collectors
- **Rule-based Detection** — YAML-based detection rules in Sigma-compatible format
- **Event Correlation** — Multi-event pattern detection (brute force, port scans, beaconing)
- **Alert Management** — Severity levels, deduplication, status tracking
- **REST API** — Comprehensive API for querying events, alerts, and managing rules
- **Persistent Storage** — SQLAlchemy with SQLite (PostgreSQL-ready)
- **Docker Support** — Multi-stage Docker build with docker-compose
- **Extensible** — Plugin-style collectors, custom rules, and correlation rules

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Runtime | Python 3.11+ |
| API Framework | FastAPI 0.115 |
| ORM | SQLAlchemy 2.0 |
| Database | SQLite (default), PostgreSQL-ready |
| Rules Format | YAML (Sigma-compatible) |
| Container | Docker (multi-stage) |
| Testing | pytest, pytest-asyncio |
| Linting | ruff, mypy |

## Quick Start

### Using Docker (recommended)

```bash
# Clone the repository
git clone https://github.com/janderik/sentinel-eye.git
cd sentinel-eye

# Start with docker-compose
docker compose up -d

# Check health
curl http://localhost:8000/api/v1/health
```

### Manual Installation

```bash
# Clone and enter directory
git clone https://github.com/janderik/sentinel-eye.git
cd sentinel-eye

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or: venv\Scripts\activate on Windows

# Install dependencies
pip install -r requirements.txt

# Run all services
python -m src.main --mode all --verbose
```

## Configuration

SentinelEye is configured via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `SENTINEL_MODE` | `all` | Run mode: `api`, `agent`, or `all` |
| `SENTINEL_HOST` | `0.0.0.0` | API server bind address |
| `SENTINEL_PORT` | `8000` | API server port |
| `SENTINEL_DB_URL` | `sqlite:///data/sentinel.db` | Database connection URL |
| `SENTINEL_RULES_DIR` | `./examples/rules` | Directory containing YAML rule files |

### Run Modes

```bash
# Run only the API server
python -m src.main --mode api --port 8080

# Run only the agent (collectors + detection engine)
python -m src.main --mode agent

# Run everything (default)
python -m src.main --mode all
```

## API Documentation

Once the API is running, visit:

- **Swagger UI**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **ReDoc**: [http://localhost:8000/redoc](http://localhost:8000/redoc)

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/health` | Health check |
| `GET` | `/api/v1/events` | List/search events |
| `GET` | `/api/v1/events/{id}` | Get event details |
| `GET` | `/api/v1/alerts` | List/search alerts |
| `GET` | `/api/v1/alerts/{id}` | Get alert details |
| `PUT` | `/api/v1/alerts/{id}/status` | Update alert status |
| `GET` | `/api/v1/rules` | List detection rules |
| `POST` | `/api/v1/rules` | Add custom rule |
| `GET` | `/api/v1/stats` | Dashboard statistics |

### Example API Calls

```bash
# Health check
curl http://localhost:8000/api/v1/health

# List events
curl "http://localhost:8000/api/v1/events?limit=10&offset=0"

# Get alerts filtered by severity
curl "http://localhost:8000/api/v1/alerts?severity=high&status=new"

# Update alert status
curl -X PUT "http://localhost:8000/api/v1/alerts/1/status?status=in_progress"

# Get dashboard stats
curl http://localhost:8000/api/v1/stats

# Add a custom rule
curl -X POST http://localhost:8000/api/v1/rules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Custom Rule",
    "source": "syslog",
    "event_type": "*",
    "severity": "medium",
    "conditions": [
      {"field": "data.host", "operator": "equals", "value": "web-01"}
    ]
  }'
```

## Rule Format

Rules are defined in YAML using the Sigma rule format:

```yaml
title: SSH Brute Force Detection
id: rule-ssh-brute-force
description: Detects multiple failed SSH authentication attempts
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    Image|endswith: "/sshd"
    CommandLine|contains: "Failed password"
  condition: selection
level: high
```

## Development

### Setup

```bash
git clone https://github.com/janderik/sentinel-eye.git
cd sentinel-eye
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=src --cov-report=term

# Run specific test file
pytest tests/test_engine.py -v
```

### Linting

```bash
ruff check src/ tests/
mypy src/
```

### Adding a New Collector

1. Create a new file in `src/collector/`
2. Inherit from `BaseCollector`
3. Implement `start()`, `stop()`, and `collect()` methods
4. Register the collector in `src/main.py`

### Adding Custom Rules

Place YAML rule files in the rules directory (default: `examples/rules/`). Rules can use:

- **Operators**: `equals`, `not_equals`, `contains`, `not_contains`, `regex`, `glob`, `gt`, `gte`, `lt`, `lte`, `in`, `not_in`, `exists`, `not_exists`
- **Field paths**: `data.*` for event data, `event.*` for event metadata

## Project Structure

```
sentinel-eye/
├── src/
│   ├── main.py                 # Entry point
│   ├── collector/
│   │   ├── base.py             # Abstract collector interface
│   │   ├── syslog.py           # Syslog (UDP/TCP) collector
│   │   └── windows_event.py    # Windows Event collector
│   ├── engine/
│   │   ├── alert.py            # Alert model and manager
│   │   ├── rules.py            # Rule engine (Sigma-compatible)
│   │   └── correlator.py       # Event correlation engine
│   ├── storage/
│   │   └── database.py         # SQLAlchemy models and session management
│   └── api/
│       ├── server.py           # FastAPI app with middleware
│       └── routes.py           # REST API routes
├── tests/
│   ├── test_collector.py
│   └── test_engine.py
├── examples/rules/
│   └── example_rules.yaml
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
