# VulnRadar

VulnRadar is an asynchronous vulnerability intelligence service in Python. It aggregates, enriches, and stores vulnerability data from multiple authoritative public threat intel sources (CISA KEV, EPSS, NVD, ExploitDB, Metasploit, PoC-in-GitHub) into PostgreSQL.

A detailed description of the components, data sources, and database schema can be found in [PROJECT_DESCRIPTION.md](PROJECT_DESCRIPTION.md).

---

## 📡 Threat Intelligence Data Sources

* **CISA KEV**: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
* **EPSS Scores**: `https://epss.cyentia.com/epss_scores-current.csv.gz`
* **NVD CVE REST API**: `https://services.nvd.nist.gov/rest/json/cves/2.0`
* **ExploitDB**: `https://www.exploit-db.com/search`
* **Metasploit Modules**: GitHub Code Search API in `rapid7/metasploit-framework`
* **GitHub PoC Index**: Nomi-sec's `PoC-in-GitHub` raw master index

---

## ⚙️ Stack & Dependencies

* **Language**: Python 3.13
* **Web framework**: `aiohttp` & `aiohttp_jinja2`
* **ORM / Database**: SQLAlchemy, Alembic, PostgreSQL (`psycopg2-binary`)
* **Automation scheduler**: APScheduler (`apscheduler`)

---

## 🚀 Setup & Installation

### 1. Create Environment Settings
Create a `.env` file in the root folder of the project. Note that `.env` is ignored by Git:

```env
DB_HOST=localhost
DB_PORT=5432
DB_NAME=vulnradar
DB_USER=postgres
DB_PASSWORD=your_password

# PostgreSQL connection string
DATABASE_URL=postgresql+psycopg2://postgres:your_password@localhost:5432/vulnradar

# Optional API Keys
NVD_API_KEY=your_nvd_api_key_here
GITHUB_TOKEN=your_github_personal_access_token_here

LOG_LEVEL=INFO
DEBUG=true
```

### 2. Configure Virtual Environment & Packages
Create and activate your Python virtual environment, then install dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Run Database Migrations
Make sure your PostgreSQL database `vulnradar` is created. Then run the Alembic migrations:

```powershell
.\.venv\Scripts\alembic upgrade head
```

---

## 🏃 Running the Application

Start the aiohttp web server:

```powershell
.\.venv\Scripts\python main.py
```

By default, the server starts on `http://127.0.0.1:8000/`.

---

## 📡 Available Web Dashboards & API Endpoints

### 🖥️ Interactive Web Dashboards
* **Root Gateway Status (`/`)**: Displays live connection status checks for the PostgreSQL database, NVD API keys, and GitHub credentials.
* **Sync Control Dashboard (`/api/v1/pipeline/sync`)**: An interactive dashboard to configure date ranges, trigger manual synchronization runs, and watch progress updates (percentage, stage, status, saved record count) in real time.

### 🔌 REST API Endpoints
* **`GET /api/v1/health`**: Performs live connection checks and returns JSON diagnostic state.
* **`POST /api/v1/pipeline/sync`**: Trigger a background sync job using a JSON body containing `start_date` and `end_date` (e.g. `{"start_date": "2026-06-01", "end_date": "2026-06-15"}`). Returns status code `202` and a `job_id`.
* **`GET /api/v1/pipeline/status/{job_id}`**: Retrieves execution details, stage, and processed count of a background sync job.
