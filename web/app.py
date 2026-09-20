"""FastAPI web service for topology-validator.

Endpoints:
    GET  /              -- HTML form for pasting a topology
    POST /validate      -- process submitted topology, render HTML report
    POST /api/validate  -- JSON API: { topology: "...", format: "json"|"text" }
    GET  /healthz       -- liveness probe for Render
"""

import base64
import io

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from topology_validator.text_parser import parse_topology_text
from topology_validator.parser import parse_devices, parse_connections
from topology_validator.graph import build_graph
from topology_validator.rules import validate_security_rules
from topology_validator.report import calculate_score
from topology_validator.visualize import visualize_topology

import os
import tempfile

app = FastAPI(
    title="toposec",
    description="Validate network topologies for security design flaws.",
    version="1.0.0",
)

templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))

def _run_validation(topo_dict):
    """Run the validator on a parsed topology dict. Returns (findings, score, png_base64)."""
    devices = parse_devices(topo_dict["devices"])
    connections = parse_connections(topo_dict["connections"], devices)
    graph = build_graph(devices, connections)
    findings = validate_security_rules(devices, graph)
    score = calculate_score(findings)
    png_buffer = io.BytesIO()
    visualize_topology(devices, graph, findings, output_path=png_buffer)
    png_bytes = png_buffer.getvalue()
    png_b64 = base64.b64encode(png_bytes).decode("ascii")

    return findings, score, png_b64


def _parse_submitted(text):
    """
    Detect whether submitted text is JSON or the PBQ-style text format,
    and return a topology dict.
    """
    stripped = text.lstrip()
    if stripped.startswith("{"):
        import json
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {e.msg} (line {e.lineno}, col {e.colno})")
        if not isinstance(data, dict) or "devices" not in data or "connections" not in data:
            raise ValueError("JSON must contain 'devices' and 'connections' keys.")
        return data
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as f:
        f.write(text)
        path = f.name
    try:
        return parse_topology_text(path)
    finally:
        os.unlink(path)


@app.get("/healthz")
def healthz():
    """Liveness probe. Render pings this to confirm the service is up."""
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    """Render the input form."""
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"result": None, "error": None},
    )

@app.post("/validate", response_class=HTMLResponse)
def validate_form(request: Request, topology: str = Form(...)):
    """Accept a submitted topology and render the report."""
    try:
        topo = _parse_submitted(topology)
        findings, score, png_b64 = _run_validation(topo)
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={
                "result": {
                    "findings": findings,
                    "score": score,
                    "png_b64": png_b64,
                    "topology_text": topology,
                },
                "error": None,
                "topology_text": topology,
            },
        )
    except (ValueError, FileNotFoundError) as e:
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={
                "result": None,
                "error": str(e),
                "topology_text": topology,
            },
        )

@app.post("/api/validate")
async def api_validate(request: Request):
    """
    JSON API endpoint.

    Request body: {"topology": "<json or text>", "include_png": false}
    Response: {"score": int, "grade": str, "findings": [...], "png_base64": "..." }
    """
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Request body must be valid JSON.")

    topology = body.get("topology")
    if not topology or not isinstance(topology, str):
        raise HTTPException(status_code=400, detail="'topology' field is required (string).")

    include_png = bool(body.get("include_png", False))

    try:
        topo = _parse_submitted(topology)
        findings, score, png_b64 = _run_validation(topo)
    except (ValueError, FileNotFoundError) as e:
        raise HTTPException(status_code=400, detail=str(e))

    response = {
        "score": score["score"],
        "grade": score["grade"],
        "counts": score["counts"],
        "findings": findings,
    }
    if include_png:
        response["png_base64"] = png_b64

    return JSONResponse(response)