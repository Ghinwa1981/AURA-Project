import datetime
from typing import List, Dict, Any
from fastapi import FastAPI, Request, HTTPException, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from services.auditor import NeuralAuditor, AuditReport

# Initialize FastAPI App
app = FastAPI(
    title="AURA (Strategic Neural Auditor)",
    description="Production-grade text security audit & integrity classification node",
    version="1.0.0"
)

# Setup Templates
templates = Jinja2Templates(directory="templates")

# Initialize Neural Auditor Core
auditor = NeuralAuditor()

# In-memory Session Database for logs
audit_history: List[Dict[str, Any]] = []

class AuditRequest(BaseModel):
    payload: str = Field(..., min_length=1, description="Text content to analyze")

@app.get("/", response_class=HTMLResponse)
async def read_index(request: Request):
    """
    Renders the AURA security dashboard interface.
    """
    # Calculate simple stats from history
    total_audits = len(audit_history)
    avg_risk = int(sum(item["risk_score"] for item in audit_history) / total_audits) if total_audits > 0 else 0
    critical_alerts = sum(1 for item in audit_history if item["risk_level"] in ("High", "Critical"))
    
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "request": request,
            "history": audit_history,
            "stats": {
                "total_audits": total_audits,
                "avg_risk": avg_risk,
                "critical_alerts": critical_alerts
            }
        }
    )


@app.post("/api/audit", response_model=AuditReport)
async def audit_payload(request: AuditRequest):
    """
    Analyzes a text payload and appends the result to session history.
    """
    try:
        report = auditor.audit(request.payload)
        
        # Add metadata and save to in-memory history
        history_entry = report.model_dump()
        history_entry["timestamp"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        history_entry["id"] = len(audit_history) + 1
        
        # Insert at the beginning of the list to show newest first
        audit_history.insert(0, history_entry)
        
        # Cap history at 100 entries
        if len(audit_history) > 100:
            audit_history.pop()
            
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Auditor internal processing failure: {str(e)}")

@app.get("/api/history")
async def get_audit_history():
    """
    Returns the session audit history logs.
    """
    return audit_history

@app.post("/api/history/clear")
async def clear_audit_history():
    """
    Clears all audit records in the current session.
    """
    audit_history.clear()
    return {"status": "success", "message": "Audit log history cleared."}
