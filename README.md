<div align="center">

<img src="https://stealthix.vercel.app/icon.png" width="75" alt="Stealthix Icon"/>

# Stealthix

### Database Injection Assessment Toolkit

### Unified SQL / NoSQL / NewSQL Security Research Platform

### ⚛ Python First ⚛ Rust Accelerated ⚛

#### Detection, Extraction, Evasion, and Reporting in One Framework

Stealthix is a unified database injection assessment and security research toolkit built with Python orchestration and a Rust-accelerated core. It provides a case-driven TUI workspace alongside a headless CLI for authorized SQL, NoSQL, and NewSQL injection detection, data extraction where supported, WAF evasion, and reporting from a single modular framework.
The platform integrates adaptive WAF bypass with 30+ tamper scripts, blind inference engines for SQL databases, heuristic NoSQL extraction, multi-target scanning with checkpoint/resume, GraphQL and WebSocket injection detection, workflow primitives for request replay and payload expansion, and reporting with CVSS scoring and compliance mapping. Stealthix supports modern database ecosystems including traditional SQL (MySQL, PostgreSQL, MSSQL, Oracle, SQLite, MariaDB, DB2, Redshift, Greenplum, Vertica, Yellowbrick, EnterpriseDB, YugabyteDB YSQL, TimescaleDB, Percona, MemSQL, Drizzle, H2, HSQLDB, Sybase, Azure Synapse, Firebird, SAP MaxDB, Informix, MonetDB, ClickHouse, Snowflake, BigQuery, Apache Derby, Presto, Trino, DuckDB, CUBRID, Altibase, MimerSQL, CrateDB, Mckoi, Cache, Virtuoso, FrontBase, Raima, eXtremeDB), NoSQL (MongoDB, CouchDB, Redis, Cassandra, DynamoDB, Firebase, ArangoDB, Couchbase, RethinkDB, OrientDB, Neo4j, JanusGraph, Amazon Neptune, Elasticsearch, Apache Solr, OpenSearch, InfluxDB, Prometheus, Aerospike, Riak, Azure Cosmos DB, Amazon DocumentDB), and NewSQL (CockroachDB, TiDB, YugabyteDB, Spanner) with varying extraction depth and proof levels per DBMS family.
With a growing ecosystem of specialized modules covering detection techniques, extraction workflows, evasion strategies, and reporting formats, Stealthix enables security researchers to orchestrate complex database injection assessments and generate professional security reports within one unified research environment.

Target your database and begin advanced injection assessment.

<br>

[![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux%20%7C%20Windows-brightgreen)](<>)
[![Version](https://img.shields.io/badge/Release-v0.1.0-red)](<>)
[![License](https://img.shields.io/badge/License-GPLv3-blue)](<>)

<a href="https://stealthix.vercel.app">
    <img width="180" src="https://img.shields.io/badge/Website-Stealthix-blue?logo=google-chrome&style=square" alt="Website"/>
</a>

<br>

</div>

## Architecture: Python + Rust Hybrid

- Python orchestrates CLI, TUI, detection modules, extraction workflows, reporting, and integrations.
- Rust powers performance-critical primitives (HTTP client, timing analysis, diff analysis, payload encoding, WAF detection, DNS exfiltration).
- The hybrid design enables Python's flexibility for complex orchestration while leveraging Rust's performance for bottleneck operations.

## Installation

### Homebrew and Scoop

The release infrastructure is prepared for Homebrew on macOS and Scoop on 64-bit x86 Windows. These channels become installable only after the public repository has a published GitHub Release and the corresponding updater workflow has validated and committed the formula or manifest.

Homebrew (after the first public release):

```bash
brew tap ImKKingshuk/tap
brew install stealthix
```

Scoop (after the first public release):

```powershell
scoop bucket add imkkingshuk https://github.com/ImKKingshuk/scoop-bucket
scoop install imkkingshuk/stealthix
```

## Quick Start

### TUI (Default)

```bash
stealthix
```

### CLI (Headless)

```bash
stealthix scan -u "https://example.test/vuln?id=1"
```

## Product Priority

- **TUI is the main product and default experience.** Use `stealthix` for interactive scanning, multi-step extraction workflows, live monitoring, and operator-guided execution.
- **Headless CLI is the secondary surface.** Use `stealthix scan ...` for quick one-off tasks, scripting, CI, and remote/headless environments.

### TUI (Default)

#### Keybindings

| Action                | Keys                    |
| --------------------- | ----------------------- |
| Quit                  | q                       |
| Navigate panels       | Tab                     |
| Move selection        | Arrow keys              |
| Open action menu      | Enter                   |
| Search modules/output | /                       |
| Help                  | ?                       |
| Theme cycle           | t                       |
| Config editor         | c                       |
| Export last result    | e                       |
| Result viewer         | v                       |
| Page scroll modules   | PageUp / PageDown       |
| Adjust panel height   | Ctrl + Up / Ctrl + Down |
| Copy result in viewer | y                       |

### TUI vs CLI

| Mode                       | Best for                                                                        | Command              |
| -------------------------- | ------------------------------------------------------------------------------- | -------------------- |
| TUI (primary)              | Interactive scanning, multi-step extraction, live output, case-first operations | `stealthix`          |
| CLI / headless (secondary) | Quick scans, automation, scripting, CI, headless servers                        | `stealthix scan ...` |

### TUI positioning vs sqlmap, NoSQLMap, and specialized tools

Stealthix is designed as a **unified injection assessment workspace** that spans SQL, NoSQL, and NewSQL detection, extraction, evasion, and reporting. The tools below are still valuable, but they solve narrower slices of the database injection workflow.

| Tool           | Primary strength                              | Main surface       | Best at                                                                       | Gaps relative to Stealthix                                                 |
| -------------- | --------------------------------------------- | ------------------ | ----------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| **Stealthix**  | Unified SQL/NoSQL/NewSQL injection assessment | Terminal TUI + CLI | Coordinating detection, extraction, evasion, and reporting from one workspace | N/A                                                                        |
| **sqlmap**     | SQL injection detection and extraction        | CLI                | Deep SQL injection techniques and data extraction                             | No NoSQL/NewSQL support, no integrated TUI, no adaptive WAF evasion        |
| **NoSQLMap**   | NoSQL injection detection                     | CLI                | MongoDB and CouchDB injection testing                                         | Limited to NoSQL, no SQL/NewSQL support, narrower integrated orchestration |
| **Burp Suite** | Web application security testing              | Web UI             | HTTP manipulation, proxy, scanner                                             | Not a database-specific injection toolkit, no blind inference engines      |

### Capability comparison: Stealthix vs specialist injection tools

| Capability                                | Stealthix  |  sqlmap  |  NoSQLMap  | Burp Suite |
| ----------------------------------------- | :--------: | :------: | :--------: | :--------: |
| Unified SQL/NoSQL/NewSQL workspace        | ✅ Native  |    ❌    |     ❌     |     ❌     |
| Blind inference engines (boolean/time)    |     ✅     |    ✅    | ⚠️ Limited |     ❌     |
| Adaptive WAF evasion (30+ scripts)        |     ✅     | ⚠️ Basic |     ❌     | ⚠️ Manual  |
| Multi-target scanning with checkpoint     |     ✅     |    ❌    |     ❌     |     ❌     |
| GraphQL/WebSocket injection               |     ✅     |    ❌    |     ❌     | ⚠️ Manual  |
| Professional reporting (CVSS, compliance) |     ✅     | ⚠️ Basic |     ❌     | ⚠️ Manual  |
| Guided operator workspace (TUI-first)     | ✅ Primary |    ❌    |     ❌     | ❌ Web UI  |
| Headless automation / scripting           |     ✅     |    ✅    |     ✅     |     ✅     |

Use Stealthix when you want one operator surface for the broader injection assessment lifecycle, and pair it with sqlmap/NoSQLMap when you need their specialist depth.

## Features Status Legend

| Icon | Status             | Meaning                                                       |
| ---- | ------------------ | ------------------------------------------------------------- |
| ✅   | `production-ready` | Stable core workflow with strong extraction support           |
| 🔧   | `functional`       | Useful and working, with practical constraints                |
| 🔬   | `best-effort`      | Works in some environments, but highly DBMS/version dependent |
| 🚧   | `experimental`     | Early workflow with notable limitations                       |
| 🔑   | `dependency-gated` | Requires optional extras, external tools, or credentials      |

## Current Capabilities (v0.1.0)

### Core Platform

- ✅ Python CLI with subcommands: `scan`, `extract`, `support`, `report`
- ✅ Full-screen TUI by default (`stealthix`) as the primary product surface; headless CLI via `stealthix scan ...` for quick/headless tasks
- ✅ Config loading via `stealthix.yaml`
- ✅ Structured logging (structlog) with Rich console output and JSON format for aggregation
- ✅ In-memory metrics collection (requests, findings, errors, latency)
- ✅ Multi-target scanning with deduplication and checkpoint/resume
- ✅ Site crawling with depth/scope control, robots.txt, sitemap parsing
- ✅ Plugin-guided DBMS selection and extraction profile resolution
- ✅ Progress callbacks for real-time scan monitoring
- ✅ Policy enforcement support (optional policy-as-code)
- 🔧 Workflow primitives for raw HTTP import, curl import, HAR import, request replay, intruder-style payload markers, template DSL expansion, and passive injection hints

### Rust Core (Native)

- ✅ High-performance HTTP client with connection pooling and async I/O
- ✅ Payload encoder (double URL encoding, obfuscation)
- ✅ Diff analyzer for boolean-based detection
- ✅ Timing analyzer with nanosecond precision for blind injection
- ✅ Error matcher for database signature detection
- ✅ WAF detector for identifying WAF vendors
- ✅ DNS exfiltration encoder for OOB callbacks
- ✅ Data extractor for structured response parsing
- ✅ Concurrent executor with ThreadPoolExecutor integration
- ✅ Rate limiter for request throttling
- ✅ 15+ tamper script functions (reverse, randomcase, space2comment, space2plus, space2tab, etc.)

### Detection & Orchestration

- ✅ SQL injection detection (boolean, time, error, union, stacked, second-order, OOB)
- 🔬 NoSQL injection detection and heuristic extraction adapters (MongoDB, CouchDB, Redis, Cassandra, Firebase, DynamoDB, ArangoDB, Couchbase, RethinkDB, OrientDB, Neo4j, JanusGraph, Amazon Neptune, Elasticsearch, Apache Solr, OpenSearch, InfluxDB, Prometheus, Aerospike, Riak, Azure Cosmos DB, Amazon DocumentDB)
- ✅ NewSQL injection detection (CockroachDB, TiDB, YugabyteDB, Spanner)
- ✅ GraphQL injection detection
- ✅ WebSocket injection detection
- ✅ IDOR checks
- ✅ Parameter discovery (GET, POST, headers, JSON bodies, XML)
- ✅ Context-aware payload application (WHERE, ORDER BY, INSERT contexts)

### Operator Workflow Primitives (🔧 Functional)

- 🔧 Raw HTTP request import, curl command import, and HAR request import normalize captured traffic into scan-ready request specs
- 🔧 Repeater workflow replays normalized requests through the existing HTTP path
- 🔧 Intruder-style payload markers support URL, header, and body expansion with shared or per-marker payload sets
- 🔧 Template DSL expansion supports reusable request generation
- 🔧 Passive hints score captured request fields for likely injection testing candidates

---

## Feature Matrix

### SQL Injection Detection (✅ Production-Ready)

- ✅ Boolean-based blind (differential response analysis)
- ✅ Error-based (database error signature matching)
- ✅ UNION-based (in-band data extraction)
- ✅ Time-based blind (high-precision timing attacks)
- ✅ Stacked queries (multiple statement execution)
- ✅ Second-order injection (stored input reflection)
- ✅ Out-of-Band (OOB/DNS callbacks)
- ✅ Blind inference engines (boolean and time-based) for MySQL, PostgreSQL, MSSQL, Oracle, SQLite, MariaDB, DB2, Redshift, Greenplum, Vertica, Yellowbrick, EnterpriseDB, YugabyteDB YSQL, TimescaleDB, Percona, MemSQL, Drizzle, H2, HSQLDB, Sybase, Azure Synapse, Firebird, SAP MaxDB, Informix, MonetDB, ClickHouse, Snowflake, BigQuery, Apache Derby, Presto, Trino, DuckDB, CUBRID, Altibase, MimerSQL, CrateDB, Mckoi, Cache, Virtuoso, FrontBase, Raima, eXtremeDB

### NoSQL Injection Detection (🔬 Best-Effort)

- 🔬 MongoDB injection (detection only, heuristic extraction)
- 🔬 CouchDB injection (detection only, heuristic extraction)
- 🔬 Redis injection (detection only, heuristic extraction)
- 🔬 Cassandra injection (detection only, heuristic extraction)
- 🔬 DynamoDB injection (detection only, heuristic extraction)
- 🔬 Firebase injection (detection only, heuristic extraction)

### NewSQL Injection Detection (🔬 Best-Effort)

- 🔬 CockroachDB injection (detection + extraction, PG-compatible)
- 🔬 TiDB injection (detection + extraction, PG-compatible)
- 🔬 YugabyteDB injection (detection + extraction, PG-compatible)
- 🔬 Spanner injection (detection only)

### Extraction (SQL: ✅, NoSQL: 🔬)

- ✅ Database enumeration (SQL: union + blind inference, NoSQL: heuristic)
- ✅ Table enumeration (SQL: union + blind inference, NoSQL: heuristic)
- ✅ Column enumeration (SQL: union + blind inference, NoSQL: heuristic)
- ✅ Table dumping (SQL: union + blind inference, NoSQL: heuristic)
- 🔬 DBMS impact planning (SQL: backend-specific file read/write, OS command, and UDF/dropper capability profiles with audit metadata and explicit operator gates)
- 🔬 File read (SQL: gated execution where profiles and extraction paths allow it; NoSQL file-impact extraction remains unsupported)
- 🔬 OS command execution (SQL: gated execution where profiles and extraction paths allow it; NoSQL OS-impact workflows remain unsupported)
- 🔬 UDF/dropper assessment (SQL: feasibility modeling only unless an operator-supplied executor is injected)

### OpSec & Evasion (✅ Production-Ready)

- ✅ Adaptive WAF bypass with vendor profiles (Cloudflare, ModSecurity, AWS WAF, Imperva, Akamai, F5, Generic)
- ✅ 30+ tamper scripts (Python + Rust implementations)
- ✅ Request throttling with adjustable delays and jitter
- ✅ Proxy rotation (HTTP(S) and SOCKS5)
- ✅ User-Agent randomization
- ✅ Adaptive retry with parameter pollution, entity encoding, request fragmentation

### Reporting (✅ Production-Ready)

- ✅ JSON reporting
- ✅ HTML reporting
- ✅ Markdown reporting
- ✅ PDF reporting (requires reportlab)
- ✅ SARIF reporting
- ✅ JUnit reporting
- ✅ CVSS v3.1 scoring
- ✅ Compliance mapping (CWE, OWASP Top 10, PCI DSS v4, NIST 800-53)

---

## Requirements

- **OS**: macOS, Linux, Windows (PowerShell or WSL)
- **Python**: 3.12+
- **Rust**: required to build the native extension from source
- **Network**: Internet connection for OOB testing

## Configuration

Stealthix looks for configuration files in the following locations (in order):

1. `./stealthix.yaml`
2. `$HOME/.config/stealthix/stealthix.yaml`
3. `$HOME/.stealthix.yaml`
4. `/etc/stealthix.yaml`

Example `stealthix.yaml`:

```yaml
url: "https://example.test"
technique: "BEUTS"
headers:
  Authorization: "Bearer ..."
risk: 3
level: 5
```

## Disclaimer

**Stealthix** is developed for research and educational purposes. It should be used responsibly and in compliance with all applicable laws and regulations. The developer of this tool is not responsible for any misuse or illegal activities conducted with this tool.

Database injection testing should only be used for legitimate purposes and with proper authorization. Using such tools without proper authorization is illegal and a violation of privacy. Ensure proper authorization before using Stealthix for security testing. Always adhere to ethical hacking practices and comply with all applicable laws and regulations.

## License

This project is licensed under the GPL-3.0-or-later License.

<h3 align="center">Use Stealthix responsibly.</h3>
