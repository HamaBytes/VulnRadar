# VulnRadar

VulnRadar is a Python service for collecting, modeling, and storing vulnerability data from the NVD API. The current backend exposes a health endpoint and uses PostgreSQL with Alembic-managed schema migrations.

## Stack

- Python 3.13
- aiohttp
- SQLAlchemy
- Alembic
- PostgreSQL
- NVD CVE API

## Project Layout

```text
main.py                  aiohttp application entry point
src/api/                 HTTP route handlers
src/models/              NVD dataclasses and SQLAlchemy database models
src/services/            config, database, fetch, enrichment, and ML services
migrations/              Alembic migration environment and versions
```

## Database

The application connects to PostgreSQL database `vulnradar` and stores application tables in schema `vulnradar`.

JDBC URL:

```text
jdbc:postgresql://localhost:5432/vulnradar
```

Example query:

```sql
select * from vulnradar.cves;
```

## Environment

Create a local `.env` file:

```env
DB_HOST=localhost
DB_PORT=5432
DB_NAME=vulnradar
DB_USER=postgres
DB_PASSWORD=your_password
NVD_API_KEY=optional_nvd_api_key
LOG_LEVEL=INFO
DEBUG=false
```

`.env` is intentionally ignored by Git.

## Setup

Create and activate a virtual environment, then install dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Run migrations:

```powershell
.\.venv\Scripts\python.exe -m alembic upgrade head
```

Check migration state:

```powershell
.\.venv\Scripts\python.exe -m alembic current
.\.venv\Scripts\python.exe -m alembic check
```

## Run

Start the API:

```powershell
.\.venv\Scripts\python.exe main.py
```

Default URL:

```text
http://127.0.0.1:8000/api/health
```

Optional runtime variables:

```env
APP_HOST=127.0.0.1
APP_PORT=8000
```

## Current Schema

The SQLAlchemy models normalize the NVD CVE payload into these tables:

```text
vulnradar.cves
vulnradar.cve_tags
vulnradar.cve_descriptions
vulnradar.cvss_metric_v2
vulnradar.cvss_data_v2
vulnradar.cve_weaknesses
vulnradar.cve_weakness_descriptions
vulnradar.cve_configurations
vulnradar.cve_nodes
vulnradar.cpe_matches
vulnradar.cve_references
```
