from fastapi import APIRouter
from app.monitor.service import (
    collect_vulnerabilities,
    search_vulnerabilities,
    enrich_vulnerability,
    export_for_chroma,
)

router = APIRouter(prefix="/monitor", tags=["monitor"])

@router.post("/collect")
def api_collect():
    return {"records": collect_vulnerabilities()}

@router.get("/search")
def api_search(q: str, top_k: int = 20):
    return {"results": search_vulnerabilities(q)}

@router.get("/enrich/{cve_id}")
def api_enrich(cve_id: str):
    return enrich_vulnerability(cve_id)

@router.get("/chroma-records")
def api_chroma_records():
    return {"records": export_for_chroma()}

@router.get("/health")
def api_health():
    from pathlib import Path
    import json
    p = Path("data/source_health.json")
    if p.exists():
        return json.loads(p.read_text(encoding="utf-8"))
    return {"sources": {}}