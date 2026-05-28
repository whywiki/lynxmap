# LynxMap

A network vulnerability scanner built for educational purposes. Scans a target host for open TCP ports, identifies running services via banner grabbing, and cross-references findings against the NVD (National Vulnerability Database) to surface known CVEs.

---

## Stack

- **Backend** - Python, FastAPI, asyncio
- **Frontend** - React, Tailwind CSS, shadcn/ui, Recharts
- **Data** - NVD API (CVE lookup), Pydantic (data models)

---

## Features

- Async TCP port scanner (parallel, fast)
- Banner grabbing - detects service name and version per port
- CVE lookup via NVD API with CPE-based version matching
- REST API with background scan jobs and polling
- CLI interface with rich terminal output
- Web dashboard for visual results

---

## Setup

### Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Create a `.env` file in the project root:

```
NVD_API_KEY=your_key_here
```

Get a free API key at https://nvd.nist.gov/developers/request-an-api-key

Start the API:

```bash
uvicorn main:app --reload --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Visit `http://localhost:5173`

---

## CLI Usage

```bash
cd backend

# Basic scan
python cli.py scan 192.168.1.1

# Custom port range
python cli.py scan 192.168.1.1 --ports 1-65535

# JSON output
python cli.py scan 192.168.1.1 --output json

# Show filtered ports
python cli.py scan 192.168.1.1 --show-filtered
```

---

## Legal Notice

Only scan hosts you own or have explicit written permission to scan. Unauthorized port scanning may be illegal in your jurisdiction. This tool is intended for educational and authorized security testing purposes only.

