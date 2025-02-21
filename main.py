from fastapi import FastAPI, Request, Form, UploadFile, File
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import os
from log_parser import LogParser
from threat_detector import ThreatDetector
from anomaly_detector import AnomalyDetector

app = FastAPI()

# ✅ Ensure FastAPI finds the templates directory
templates = Jinja2Templates(directory="templates")

# Initialize detectors
threat_detector = ThreatDetector()
anomaly_detector = AnomalyDetector()

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Renders the homepage with an upload form."""
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/analyze-log/")
async def analyze_log(log: str = Form(...)):
    """Analyzes a single log entry for threats and anomalies."""
    is_threat = threat_detector.detect_threat(log)
    is_anomaly = anomaly_detector.detect_anomaly(log)

    return {
        "log": log,
        "threat_detected": is_threat,
        "anomaly_detected": is_anomaly
    }

@app.post("/upload-logfile/")
async def upload_logfile(file: UploadFile = File(...)):
    """Handles log file uploads, parses them, and detects threats/anomalies."""
    file_location = f"logs/{file.filename}"

    # Save the uploaded file
    with open(file_location, "wb") as f:
        f.write(file.file.read())

    # Parse and analyze logs
    parser = LogParser(file_location)
    parsed_logs = parser.read_logs()

    results = []
    for log in parsed_logs:
        is_threat, is_anomaly = parser.analyze_log(log)
        results.append({
            "log": log.message,
            "threat_detected": is_threat,
            "anomaly_detected": is_anomaly
        })

    return {"filename": file.filename, "results": results}
