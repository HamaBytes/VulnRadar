# VulnRadar — Project Description & Reference Guide

VulnRadar is an advanced, asynchronous Python-based vulnerability intelligence service. It aggregates, enriches, and stores vulnerability data from multiple authoritative public sources to provide security teams with a unified view of threat intelligence.

---

## 📡 Threat Intelligence Data Sources

VulnRadar pulls data from various endpoints to build a multi-layered profile of each vulnerability:

1. **CISA KEV (Known Exploited Vulnerabilities)**:
   * **Purpose**: Serves as the starting catalog of vulnerabilities that are actively being exploited in the wild.
   * **Source URL**: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

2. **EPSS (Exploit Prediction Scoring System)**:
   * **Purpose**: Provides the probability (0.0 to 1.0) and percentile rankings representing the likelihood that a vulnerability will be exploited in the next 30 days.
   * **Source URL**: `https://epss.cyentia.com/epss_scores-current.csv.gz` (maintained by Cyentia/FIRST.org).

3. **NVD (National Vulnerability Database)**:
   * **Purpose**: Pulls detailed CVSS scores (v2, v3, and v4), severity, descriptions, weaknesses (CWE), CPE configurations, and references.
   * **Source URL**: `https://services.nvd.nist.gov/rest/json/cves/2.0` (National Institute of Standards and Technology - NIST).

4. **Exploit Intelligence Sources**:
   * **ExploitDB**: Direct search API (`https://www.exploit-db.com/search`) retrieving verified, public proof-of-concept exploits.
   * **Metasploit Framework**: GitHub Code Search API (`https://api.github.com/search/code` in `rapid7/metasploit-framework`) to map vulnerabilities to active Metasploit integration modules.
   * **PoC-in-GitHub**: Raw repository index by nomi-sec (`https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master`) mapping CVEs to active public repositories on GitHub.

---

## 🏗️ Architecture & Component Layers

VulnRadar follows a clean, layered architecture ensuring single responsibility, dependency injection, and robustness:

```mermaid
graph TB
    subgraph Clients["🌐 Client Layer"]
        WEB["Browser (Web Dashboards)"]
        CLI["API Consumer (cURL / Postman)"]
    end

    subgraph API["🔌 API Layer (src/api/)"]
        MW_RATE["Rate Limiter Middleware"]
        R_GATEWAY["GET / (Gateway Status)"]
        R_HEALTH["GET /api/v1/health"]
        R_SYNC_DASH["GET /api/v1/pipeline/sync"]
        R_SYNC_TRIG["POST /api/v1/pipeline/sync"]
        R_STATUS["GET /api/v1/pipeline/status/:job_id"]
    end

    subgraph Services["⚙️ Sync Engine (src/services/ & src/fetchers/)"]
        PIPE["pipelines.py (Orchestrator)"]
        ENRICH["enrichment.py (3-Stage Enricher)"]
        F_KEV["kev_fetcher_async.py"]
        F_EPSS["epss_fetcher_async.py"]
        F_NVD["nvd_fetcher_async.py"]
        F_EXP["exploit_fetcher_async.py"]
    end

    subgraph Storage["🗃️ Storage Layer (src/models/ & src/services/Database/)"]
        DB_STORE["DatabaseStorage"]
        ORM_MODELS["SQLAlchemy Models"]
        DB[(PostgreSQL - vulnradar schema)]
    end

    subgraph Jobs["⏰ Automation (src/jobs/)"]
        SCHED["APScheduler (AsyncIOScheduler)"]
    end

    %% Routing
    Clients --> MW_RATE
    MW_RATE --> R_GATEWAY & R_HEALTH & R_SYNC_DASH & R_SYNC_TRIG & R_STATUS

    %% Handlers -> Services & Jobs
    R_SYNC_TRIG -.->|Launch Task| PIPE
    R_STATUS -.->|Query Status| R_SYNC_TRIG
    SCHED -->|Daily Trigger| PIPE

    %% Pipeline Execution
    PIPE --> F_KEV
    PIPE --> ENRICH
    ENRICH --> F_EPSS & F_NVD & F_EXP
    
    %% Storage
    PIPE --> DB_STORE
    DB_STORE --> ORM_MODELS --> DB
```

### Directory Structure

```text
VulnRadar/
├── main.py                        # Server startup & App Factory configuration
├── alembic.ini                    # Alembic Database migration configuration
├── requirements.txt               # Project dependency specifications
├── migrations/                    # Alembic schema version history
│
└── src/
    ├── api/                       # API HTTP delivery layer
    │   ├── middleware/            # Request interceptors (e.g. rate limiter)
    │   │   └── rate_limiter.py    # Token bucket rate limiting middleware
    │   ├── v1/                    # API v1 routes & handlers
    │   │   ├── health.py          # API connection and authentication status
    │   │   └── pipeline.py        # Pipeline trigger and status monitoring
    │   └── router.py              # Central router registration
    │
    ├── config/                    # Global runtime settings
    │   ├── config.py              # Environment settings parser
    │   └── database.py            # SQLAlchemy engine & session factory
    │
    ├── fetchers/                  # Asynchronous data collectors
    │   ├── epss_fetcher_async.py  # Cyentia/FIRST.org EPSS downloader
    │   ├── exploit_fetcher_async.py # ExploitDB, MSF, and Github PoC search
    │   ├── kev_fetcher_async.py   # CISA KEV fetcher
    │   ├── nvd_fetcher_async.py   # NVD CVE details fetcher
    │   └── pipelines.py           # Sync pipeline orchestrator
    │
    ├── jobs/                      # Automation & scheduling
    │   └── scheduler.py           # APScheduler background sync manager
    │
    ├── models/                    # SQLAlchemy database schema models
    │   ├── db_base.py             # Declares base metadata & schema namespace
    │   ├── cve.py                 # Core vulnerability index table
    │   ├── epss.py                # EPSS score mapping table
    │   ├── exploit.py             # PoC exploit reference mapping table
    │   ├── nvd.py                 # Normalized NVD tables (descriptions, CVSS, CPEs)
    │   ├── weakness.py            # Weaknesses (CWE) relationships
    │   └── configuration.py       # Configuration nodes (CPE matching)
    │
    ├── services/                  # Business logic services
    │   ├── Database/
    │   │   └── storage.py         # Handles upserting bulk CVE payloads
    │   └── enrichment.py          # 3-Stage vulnerability enricher
    │
    ├── static/                    # Placeholders for static web resources
    └── templates/                 # Jinja2 HTML templates
        ├── gateway_status.html    # Connection / health room status UI
        └── sync_dashboard.html    # Dynamic pipeline controller & monitor UI
```

---

## 🗄️ Database Schema & Normalization

VulnRadar structures data in the `vulnradar` PostgreSQL schema. Below is a breakdown of the primary tables and relationships:

```mermaid
erDiagram
    cves ||--|| epss : "has score"
    cves ||--o{ exploit_references : "contains PoCs"
    cves ||--o{ cve_descriptions : "contains descriptions"
    cves ||--o{ cvss_metric_v2 : "has cvss v2"
    cves ||--o{ cve_weaknesses : "associated weaknesses"
    cves ||--o{ cve_configurations : "affects configurations"
    cves ||--o{ cve_references : "linked references"

    cves {
        bigint id PK
        string cve_id UK
        string source_identifier
        string title
        text description
        decimal cvss_v3_score
        string severity
        datetime published_date
        datetime last_modified_date
        string vuln_status
        datetime created_at
    }

    epss {
        bigint id PK
        bigint cve_db_id FK
        string cve_id
        decimal epss_score
        decimal percentile
    }

    exploit_references {
        bigint id PK
        bigint cve_db_id FK
        string cve_id
        string source
        text url
        string exploit_id
        text title
        string module
    }
```

---

## ⚡ Synchronization Engine

The sync engine operates either in **Background mode (Scheduler)** or **Manual mode (Dashboard)**:

1. **3-Stage Enrichment**:
   * **Stage 1 (EPSS)**: Downloads the cyentia gzipped CSV in-memory, parses it, and maps it directly via memory lookup.
   * **Stage 2 (NVD)**: Queries the NIST REST API per-CVE to extract base scores, weaknesses, configurations, and reference urls.
   * **Stage 3 (Exploits)**: Queries ExploitDB, Metasploit, and PoC-in-GitHub concurrently via `asyncio.gather`.

2. **Incremental Sync Logic**:
   * When scheduled daily, the system queries the local database to find the latest `published_date` of all stored vulnerabilities.
   * It then fetches the CISA KEV list and filters out any entries added before this date. Only the delta is processed and saved.

3. **Background Scheduler (APScheduler)**:
   * Initializes clean lifecycle hooks on server startup/shutdown.
   * Runs daily in the background to execute incremental synchronization without server disruption.

4. **Interactive Dashboard Progress**:
   * Served at `GET /api/v1/pipeline/sync`.
   * Displays the sync stage (`EPSS`, `NVD`, `Exploits`, `Saving`), records processed, and dynamic progress percentage in real time.

---

## 🔒 Security & Protection Middleware

* **Token Bucket Rate Limiting**:
  * An IP-based rate limiter middleware tracks incoming requests in memory.
  * Defaults to `60 requests per minute`. Exceeding this triggers an automatic `429 Too Many Requests` response.

---

## 📡 API Endpoints (v1)

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Root gateway status dashboard. Checks DB, NVD key, and GitHub token presence. |
| `GET` | `/api/v1/health` | Raw connection, remaining NVD and GitHub request capacities. |
| `GET` | `/api/v1/pipeline/sync` | HTML interface to trigger and monitor manual synchronizations. |
| `POST` | `/api/v1/pipeline/sync` | Starts a background synchronization task. Expects JSON start/end dates. |
| `GET` | `/api/v1/pipeline/status/{job_id}`| Polls current stats (processed, total, status, saved records, and CVE ids). |
