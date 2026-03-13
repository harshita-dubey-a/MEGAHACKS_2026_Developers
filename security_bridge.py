from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import subprocess
import json
import os
import uuid
import time
import httpx
from fastapi import Request, Response
from typing import List, Optional, Dict, Any

import re

app = FastAPI(title="Security Sentinel Bridge")

def strip_ansi(text):
    return re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', text)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for scan data
scans_db: Dict[str, dict] = {}

class ScanRequest(BaseModel):
    target: str
    probes: Optional[str] = "all"
    generations: Optional[int] = 5

class NmapRequest(BaseModel):
    target: str
    ports: Optional[List[int]] = None

@app.get("/health")
def health():
    return {"status": "ok"}

# --- NMAP ENDPOINT (Preserved) ---
# --- NMAP ENDPOINT (ASYNCHRONOUS) ---

@app.post("/api/v1/nmap/scan")
async def start_nmap_scan(request: NmapRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    scans_db[scan_id] = {
        "scan_id": scan_id,
        "type": "nmap",
        "target": request.target,
        "status": "started",
        "progress": 0,
        "message": "Initializing Nmap...",
        "logs": [],
        "results": []
    }
    
    def run_worker(sid, target, ports_list):
        try:
            ports = ",".join(map(str, ports_list)) if ports_list else "21-443"
            cmd = ["nmap", "-sT", "-p", ports, target, "-oX", "-"]
            
            scans_db[sid]["status"] = "running"
            scans_db[sid]["message"] = f"Scanning {target}..."
            
            # Using Popen to capture logs in real-time
            # Note: Nmap XML output is buffered, so we might not see "live" results in XML easily
            # but we can capture the regular output too or just simulate progress
            process = subprocess.Popen(
                ["nmap", "-sT", "-p", ports, target, "-v"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            
            for line in process.stdout:
                line_clean = strip_ansi(line.strip())
                if line_clean:
                    scans_db[sid]["logs"].append(line_clean)
                    # Simple progress heuristic
                    if "Scanning" in line_clean and "%" in line_clean:
                        try:
                            scans_db[sid]["progress"] = int(re.search(r'(\d+)%', line_clean).group(1))
                        except: pass
            
            process.wait()
            
            # Now run the XML version for the final parsed results
            xml_proc = subprocess.run(
                ["nmap", "-sT", "-p", ports, target, "-oX", "-"],
                capture_output=True, text=True
            )
            
            scans_db[sid]["raw_output"] = xml_proc.stdout
            scans_db[sid]["status"] = "completed"
            scans_db[sid]["progress"] = 100
            scans_db[sid]["message"] = "Scan completed"
            
        except Exception as e:
            scans_db[sid]["status"] = "failed"
            scans_db[sid]["message"] = str(e)

    background_tasks.add_task(run_worker, scan_id, request.target, request.ports)
    return {"scan_id": scan_id, "status": "started"}

@app.get("/api/v1/nmap/status/{scan_id}")
async def get_nmap_status(scan_id: str):
    if scan_id not in scans_db:
        raise HTTPException(status_code=404, detail="Scan not found")
    data = scans_db[scan_id]
    return {
        "scan_id": data["scan_id"],
        "status": data["status"],
        "progress": data["progress"],
        "message": data["message"],
        "logs": data.get("logs", [])[-50:], # Return last 50 lines
        "raw_output": data.get("raw_output", "")
    }

# --- GARAK API (REQUESTED STRUCTURE) ---

@app.get("/api/v1/garak/models")
async def list_models(limit: int = 50):
    """List available LLM generators from Garak."""
    try:
        process = subprocess.run(
            ["python3", "-m", "garak", "--list_generators"],
            capture_output=True, text=True
        )
        raw_models = [line.strip() for line in process.stdout.split("\n") if line.strip() and not line.startswith("garak")]
        models = [strip_ansi(m).replace("generators: ", "").strip() for m in raw_models]
        return models[:limit]
    except Exception as e:
        return ["openai.GPT4", "openai.GPT35", "huggingface.gpt2", "replicate.llama2"] # Fallback

@app.get("/api/v1/garak/probes")
async def list_probes():
    """List available Garak probes."""
    try:
        process = subprocess.run(
            ["python3", "-m", "garak", "--list_probes"],
            capture_output=True, text=True
        )
        raw_probes = [line.strip() for line in process.stdout.split("\n") if line.strip() and not line.startswith("garak")]
        probes = [strip_ansi(p).replace("probes: ", "").strip() for p in raw_probes]
        return probes
    except Exception as e:
        return ["dan.Dan_6_0", "jailbreak.Jailbreak", "lmrc.Profanity"] # Fallback

@app.post("/api/v1/garak/scan")
async def start_garak_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    scans_db[scan_id] = {
        "scan_id": scan_id,
        "type": "garak",
        "status": "started",
        "progress": 0,
        "message": "Initializing scan...",
        "logs": [],
        "results": []
    }
    
    def run_worker(sid, target, probes, gens):
        try:
            cmd = ["python3", "-m", "garak", "--model_type", "openai", "--model_name", target, "--probes", probes, "--report_prefix", f"garak_run_{sid}"]
            
            scans_db[sid]["message"] = "Scanning in progress..."
            scans_db[sid]["status"] = "running"
            
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            
            for line in process.stdout:
                line_clean = strip_ansi(line.strip())
                if line_clean:
                    scans_db[sid]["logs"].append(line_clean)
                    # Attempt to parse progress if garak provides it
                    if "generation" in line_clean.lower():
                        scans_db[sid]["progress"] = min(95, scans_db[sid]["progress"] + 5)
            
            process.wait()
            
            # Garak reports are usually saved as {prefix}.report.jsonl
            report_path = f"garak_run_{sid}.report.jsonl"
            
            # If not in CWD, garak might have put it in a default location
            # but usually it's in the same dir as the prefix
            
            results = []
            if os.path.exists(report_path):
                scans_db[sid]["message"] = "Parsing results..."
                with open(report_path, "r") as f:
                    for line in f:
                        try:
                            entry = json.loads(line)
                            # entry_type 1=init, 2=attempt, 3=evaluated
                            # We only care about evaluated entries that failed
                            if entry.get("entry_type") == "evaluated" and entry.get("passed") is False:
                                results.append({
                                    "id": str(uuid.uuid4()),
                                    "scanner": "Garak",
                                    "name": f"Garak Probe: {entry.get('probe', 'Unknown')}",
                                    "severity": "high",
                                    "url": target,
                                    "asset": "LLM Model",
                                    "description": f"Goal: {entry.get('goal', 'N/A')}\nPrompt: {entry.get('prompt', 'N/A')}\nDetector: {entry.get('detector', 'N/A')}",
                                    "risk_score": 8.0,
                                    "confidence": "High",
                                    "probe": entry.get("probe"),
                                    "detector": entry.get("detector"),
                                    "passed": False
                                })
                        except: pass
                
                scans_db[sid]["results"] = results
                scans_db[sid]["status"] = "completed"
                scans_db[sid]["progress"] = 100
                scans_db[sid]["message"] = f"Scan completed with {len(results)} findings"
                
                # Cleanup report file if desired, or keep it
                # os.remove(report_path)
            else:
                # Check if it was saved in garak's default reports dir
                # but for simplicity, if it's not here, we check typical locations
                scans_db[sid]["status"] = "completed"
                scans_db[sid]["progress"] = 100
                scans_db[sid]["message"] = "Scan completed (no report file found or no findings)"
                scans_db[sid]["results"] = []
        except Exception as e:
            scans_db[sid]["status"] = "failed"
            scans_db[sid]["message"] = str(e)

    background_tasks.add_task(run_worker, scan_id, request.target, request.probes, request.generations)
    return {"scan_id": scan_id, "status": "started"}

@app.get("/api/v1/garak/status/{scan_id}")
async def get_garak_status(scan_id: str):
    if scan_id not in scans_db:
        raise HTTPException(status_code=404, detail="Scan not found")
    data = scans_db[scan_id]
    return {
        "scan_id": data["scan_id"],
        "status": data["status"],
        "progress": data["progress"],
        "message": data["message"],
        "logs": data.get("logs", [])[-50:]
    }

@app.get("/api/v1/garak/results/{scan_id}")
async def get_scan_results(scan_id: str):
    if scan_id not in scans_db:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scans_db[scan_id]["results"]

# --- ACUNETIX PROXY ---
ACUNETIX_BASE = "https://kali:3443/api/v1"

@app.api_route("/api/v1/acunetix/{path:path}", methods=["GET", "POST", "PATCH", "DELETE", "PUT"])
async def acunetix_proxy(request: Request, path: str):
    # Standardize the path - ensure it doesn't have double slashes
    clean_path = path.lstrip("/")
    url = f"{ACUNETIX_BASE}/{clean_path}"
    
    # Forward query parameters
    if request.query_params:
        url += f"?{request.query_params}"
        
    # Extract headers (excluding host and content-length)
    headers = {k: v for k, v in request.headers.items() if k.lower() not in ["host", "content-length", "connection"]}
    
    # Read body
    body = await request.body()
    
    try:
        async with httpx.AsyncClient(verify=False, timeout=60.0) as client:
            resp = await client.request(
                method=request.method,
                url=url,
                headers=headers,
                content=body
            )
            
            # Return response
            return Response(
                content=resp.content,
                status_code=resp.status_code,
                headers={k: v for k, v in resp.headers.items() if k.lower() not in ["content-encoding", "transfer-encoding", "content-length", "connection"]}
            )
    except Exception as e:
        print(f"Proxy Error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Proxy error: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
