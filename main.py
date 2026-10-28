import os
import json
import glob
import queue
import threading
import asyncio
import time
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from starlette.responses import StreamingResponse
from starlette.staticfiles import StaticFiles
from pydantic import BaseModel
import ollama

from models.skill import SkillManifest
from engine.scanner import ASTScanner
from engine.ai_reasoner import AIReasoner
from engine.attack_agent import AttackAgent
from engine.attacks import ALL_ATTACKS, ATTACK_REGISTRY

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

app = FastAPI(title="SkillGuard - AI Pentest Agent & Defensive Gateway")
scanner = ASTScanner()
reasoner = AIReasoner()


class ScanRequest(BaseModel):
    url: str


class AttackRequest(BaseModel):
    url: str
    model: str = "gemma:latest"


# ── Root & Static Interface ───────────────────────────────────────────────

@app.get("/")
async def root(request: Request):
    accept_header = request.headers.get("accept", "")
    # If requested by a web browser, serve the interactive UI
    if "text/html" in accept_header and os.path.exists(os.path.join(STATIC_DIR, "index.html")):
        return FileResponse(os.path.join(STATIC_DIR, "index.html"))
    # Default JSON response for tests and API clients
    return {"status": "SkillGuard is running", "mode": "pentest-agent"}


@app.get("/agent")
@app.get("/dashboard")
@app.get("/app")
async def agent_dashboard():
    agent_path = os.path.join(STATIC_DIR, "agent.html")
    if os.path.exists(agent_path):
        return FileResponse(agent_path)
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"error": "UI not built yet"}


# ── Core Endpoints ────────────────────────────────────────────────────────

@app.post("/api/v1/verify-skill")
async def verify_skill(manifest: SkillManifest):
    result = scanner.evaluate(manifest)
    result["ai_explanation"] = reasoner.explain_findings(
        manifest.instructions, result["findings"]
    )
    return result


@app.post("/api/v1/scan-website")
async def scan_website(request: ScanRequest):
    from engine.web_scanner import WebScanner

    web_scanner = WebScanner(request.url)
    result = web_scanner.scan()

    risk = reasoner.calculate_risk_score(result["findings"])
    result["risk_score"] = risk["score"]
    result["risk_grade"] = risk["grade"]

    result["ai_report"] = reasoner.explain_findings(
        f"Website security scan of {result['target']}", result["findings"]
    )
    return result


@app.post("/api/v1/attack")
async def run_attack(request: AttackRequest):
    """
    Launch the autonomous AI-driven pentest agent (Synchronous).
    """
    agent = AttackAgent(target_url=request.url, model=request.model)
    report = agent.run_full_pentest()
    return report


# ── Real-Time Streaming Agent Execution (SSE) ────────────────────────────

@app.get("/api/v1/attack/stream")
async def stream_attack(url: str, model: str = "gemma:latest"):
    """
    Server-Sent Events (SSE) stream for real-time agent execution progress,
    including live terminal logs, AI neural decisions, module results, and final report.
    """
    event_queue: queue.Queue = queue.Queue()

    def event_emitter(event_type: str, data: dict):
        event_queue.put({"event": event_type, "data": data})

    def worker():
        try:
            event_emitter("start", {"target": url, "model": model, "timestamp": time.time()})
            agent = AttackAgent(target_url=url, model=model, event_callback=event_emitter)
            report = agent.run_full_pentest()
            event_emitter("finished", {"report": report})
        except Exception as e:
            event_emitter("error", {"message": str(e)})
        finally:
            event_queue.put(None)  # Sentinel to terminate generator

    threading.Thread(target=worker, daemon=True).start()

    async def event_generator():
        while True:
            while event_queue.empty():
                await asyncio.sleep(0.08)
            item = event_queue.get()
            if item is None:
                break
            payload = json.dumps(item)
            yield f"data: {payload}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ── System Info & Models ──────────────────────────────────────────────────

@app.get("/api/v1/system-status")
async def system_status():
    ollama_ok = False
    detected_models = []
    try:
        model_list = ollama.list()
        detected_models = [m.model for m in model_list.models] if hasattr(model_list, "models") else []
        ollama_ok = True
    except Exception:
        ollama_ok = False

    return {
        "status": "online",
        "ollama_connected": ollama_ok,
        "available_models": detected_models if detected_models else ["gemma:latest", "llama3:latest"],
        "registered_attacks": ALL_ATTACKS,
        "reports_count": len(glob.glob(os.path.join(REPORTS_DIR, "*.md"))),
    }


@app.get("/api/v1/models")
async def list_models():
    try:
        model_list = ollama.list()
        models = [
            {
                "name": m.model,
                "size": getattr(m, "size", 0),
                "modified_at": str(getattr(m, "modified_at", "")),
            }
            for m in getattr(model_list, "models", [])
        ]
        if not models:
            models = [{"name": "gemma:latest", "size": 0, "modified_at": "default"}]
        return {"models": models}
    except Exception:
        return {"models": [{"name": "gemma:latest", "size": 0, "modified_at": "default"}]}


# ── Reports Vault ────────────────────────────────────────────────────────

class ExportPdfRequest(BaseModel):
    markdown: str
    target: str = "Target"
    domain: str = "target"
    score: int = 75
    grade: str = "B"
    findings: list[dict] = []


@app.get("/api/v1/reports")
async def list_reports():
    reports = []
    for filepath in glob.glob(os.path.join(REPORTS_DIR, "*.md")):
        fname = os.path.basename(filepath)
        stat = os.stat(filepath)
        # Parse target from filename: pentest_{domain}_{timestamp}.md
        parts = fname.replace(".md", "").split("_")
        domain = parts[1] if len(parts) >= 2 else "unknown"
        pdf_name = fname.replace(".md", ".pdf")
        has_pdf = os.path.exists(os.path.join(REPORTS_DIR, pdf_name))
        reports.append({
            "filename": fname,
            "pdf_filename": pdf_name,
            "has_pdf": has_pdf,
            "domain": domain,
            "size_bytes": stat.st_size,
            "modified_time": stat.st_mtime,
            "modified_str": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime)),
        })
    # Sort newest first
    reports.sort(key=lambda r: r["modified_time"], reverse=True)
    return {"reports": reports}


@app.get("/api/v1/reports/{filename}")
async def get_report(filename: str):
    # Prevent directory traversal
    safe_name = os.path.basename(filename)
    filepath = os.path.join(REPORTS_DIR, safe_name)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Report not found")
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()
    stat = os.stat(filepath)
    return {
        "filename": safe_name,
        "content": content,
        "size_bytes": stat.st_size,
        "modified_str": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime)),
    }


@app.get("/api/v1/reports/{filename}/pdf")
async def get_report_pdf(filename: str):
    """
    Generate or stream executive penetration test dossier PDF.
    """
    safe_name = os.path.basename(filename)
    if safe_name.endswith(".pdf"):
        pdf_name = safe_name
        md_name = safe_name.replace(".pdf", ".md")
    else:
        md_name = safe_name if safe_name.endswith(".md") else safe_name + ".md"
        pdf_name = md_name.replace(".md", ".pdf")

    pdf_path = os.path.join(REPORTS_DIR, pdf_name)
    md_path = os.path.join(REPORTS_DIR, md_name)

    if not os.path.exists(md_path):
        raise HTTPException(status_code=404, detail="Report markdown source not found")

    with open(md_path, "r", encoding="utf-8") as f:
        content = f.read()

    # If PDF already generated and is newer than markdown, serve it directly
    if os.path.exists(pdf_path) and os.path.getmtime(pdf_path) >= os.path.getmtime(md_path) and os.path.getsize(pdf_path) > 1000:
        return FileResponse(
            pdf_path,
            media_type="application/pdf",
            filename=pdf_name,
            headers={"Content-Disposition": f'attachment; filename="{pdf_name}"'},
        )

    parts = md_name.replace(".md", "").split("_")
    domain = parts[1] if len(parts) >= 2 else "target"
    target = f"https://{domain}" if not domain.startswith("http") else domain

    try:
        from engine.pdf_generator import SkillGuardPDFGenerator
        gen = SkillGuardPDFGenerator()
        gen.build_pdf(
            target=target,
            output_filepath=pdf_path,
            raw_markdown=content,
        )
        return FileResponse(
            pdf_path,
            media_type="application/pdf",
            filename=pdf_name,
            headers={"Content-Disposition": f'attachment; filename="{pdf_name}"'},
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF generation error: {str(e)}")


@app.post("/api/v1/reports/export-pdf")
async def export_custom_pdf(request: ExportPdfRequest):
    """
    Generate on-the-fly PDF from custom pentest report parameters and return download.
    """
    safe_domain = request.domain.replace(":", "_").replace("/", "_")
    pdf_filename = f"pentest_{safe_domain}_{int(time.time())}.pdf"
    pdf_path = os.path.join(REPORTS_DIR, pdf_filename)
    try:
        from engine.pdf_generator import SkillGuardPDFGenerator
        gen = SkillGuardPDFGenerator()
        gen.build_pdf(
            target=request.target,
            output_filepath=pdf_path,
            risk_score=request.score,
            risk_grade=request.grade,
            all_findings=request.findings,
            raw_markdown=request.markdown,
        )
        return FileResponse(
            pdf_path,
            media_type="application/pdf",
            filename=pdf_filename,
            headers={"Content-Disposition": f'attachment; filename="{pdf_filename}"'},
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF export failed: {str(e)}")



# ── Static Mount (at end so API routes match first) ──────────────────────

if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")