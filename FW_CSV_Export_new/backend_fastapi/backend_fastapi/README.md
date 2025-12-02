# Backend (FastAPI)

## Folder layout
```
backend_fastapi/
├─ app/
│  ├─ main.py
│  └─ mcp/
│     ├─ (PUT your MCP Python scripts here)
│     └─ .gitkeep
├─ data/
│  └─ uploads/   # uploaded files saved here
├─ requirements.txt
└─ README.md
```

> Copy the following MCP scripts into `app/mcp/`:
- `Parent_Rule_mcp_Server.py`
- `Rule_base_combined.py`
- `Address_mcp.py`
- `Services_mcp.py`
- `Application_mcp.py`

These are the same files you already have. The API imports functions directly from `Parent_Rule_mcp_Server.py`.

## Create & run (Linux/macOS/WSL)
```bash
cd backend_fastapi
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# (optional) verify python can import app.mcp.Parent_Rule_mcp_Server after copying files
# ls app/mcp/

uvicorn app.main:app --reload --port 8000
```

## API
- `POST /api/upload` (multipart) → returns saved server paths
- `POST /api/run/address-expand` → runs `run_pipeline_address_expand`
- `POST /api/run/services-applications` → runs `run_pipeline_services_applications`
- `POST /api/run/all` → runs `run_pipeline_all`
- `POST /api/run/export-curated` → runs `run_export_curated_to_new_excel`
- `GET /api/download?path=...` → downloads generated files (whitelisted to `./data`)

### Advanced Analysis Endpoints
- `POST /api/analyze` → Run advanced policy analysis (Shadow Rules, Redundancies, Generalizations, Correlations, Consolidations)
- `GET /api/analyze/progress/{session_id}` → Get progress information for an ongoing analysis
- `GET /api/analyze/stream/{session_id}` → Stream real-time progress via Server-Sent Events (SSE)
- `GET /api/download-analysis?id={download_id}` → Download analyzed Excel file

> All run endpoints accept **optional JSON** overriding paths/columns just like the Python tools.
> 
> The advanced analysis endpoints are served by the same uvicorn instance on port 8000, alongside the dashboard analysis endpoints.
