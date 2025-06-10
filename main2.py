from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import FileResponse
from email import policy
from email.parser import BytesParser
import joblib
import re
import os
import csv
import uuid
import requests
from dotenv import load_dotenv
import magic
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

# Load environment variables from .env file
load_dotenv()

# Initialize FastAPI app
app = FastAPI()

# Serve static files from the "static" directory
app.mount("/static", StaticFiles(directory="static"), name="static")

# Load the machine learning model for phishing detection
model = joblib.load("phishing_model.pkl")

# Helper function to analyze email headers
def analyze_headers(msg):
    hdrs = {
        "SPF": "Missing",
        "DKIM": "Missing",
        "DMARC": "Missing"
    }
     # Check SPF record
    if msg.get("Received-SPF"):
        hdrs["SPF"] = "Pass" if "pass" in msg.get("Received-SPF").lower() else "Fail"
    # Check DKIM signature
    if msg.get("DKIM-Signature"):
        hdrs["DKIM"] = "Present"
    # Check DMARC authentication result
    if msg.get("Authentication-Results") and 'dmarc' in msg.get("Authentication-Results").lower():
        auth = msg.get("Authentication-Results").lower()
        if "dmarc=pass" in auth:
            hdrs["DMARC"] = "Pass"
        elif "dmarc=fail" in auth:
            hdrs["DMARC"] = "Fail"
    return hdrs

# 🧠 Helper function to extract URLs from email body
def extract_urls(body):
    return re.findall(r'https?://\S+', body)

# 🔍 Scan URL using urlscan.io
def scan_url(url):
    api_key = os.getenv("URLSCAN_API_KEY")
    headers = {"API-Key": api_key, "Content-Type": "application/json"}
    data = {"url": url, "visibility": "public"}
    try:
        res = requests.post("https://urlscan.io/api/v1/scan/", headers=headers, json=data)
        if res.status_code == 200:
            return {"url": url, "scan_id": res.json().get("uuid")}
        else:
            return {"url": url, "error": "Scan failed"}
    except Exception:
        return {"url": url, "error": "Scan failed"}

# Helper function to scan email attachments
def scan_attachments(msg):
    results = []
    for part in msg.iter_attachments():
        content = part.get_payload(decode=True)
        filename = part.get_filename()
        if filename:
            mime = magic.from_buffer(content, mime=True)
            results.append({
                "filename": filename,
                "mime_type": mime,
                "size_bytes": len(content),
                "suspicious": filename.endswith(('.exe', '.js', '.scr', '.vbs'))
            })
    return results

# 📥 Global dict to hold latest report
latest_report = {}

# 🧠 Analyze email API route: Endpoint to analyze uploaded email files
@app.post("/analyze/")
async def analyze_email(file: UploadFile = File(...)):
    file_bytes = await file.read()
    msg = BytesParser(policy=policy.default).parsebytes(file_bytes)

    # Extract email body text
    body = msg.get_body(preferencelist=('plain', 'html'))
    text = body.get_content() if body else ""
    urls = extract_urls(text)
    url_scans = [scan_url(u) for u in urls]

    # Run phishing detection model prediction
    header_results = analyze_headers(msg)
    phishing_prediction = model.predict([text])[0]
    attachment_results = scan_attachments(msg)

    # Compile results into a report
    result = {
        "Header Analysis": header_results,
        "Phishing Detection": "Phishing" if phishing_prediction else "Legit",
        "Extracted URLs": urls,
        "URL Scan Results": url_scans,
        "Attachment Scan": attachment_results
    }

    # Generate unique report ID and save results to CSV
    report_id = str(uuid.uuid4())
    filename_csv = f"report_{report_id}.csv"
    latest_report["csv"] = filename_csv

    #  Save analysis results to CSV
    with open(filename_csv, "w", newline='') as cf:
        writer = csv.writer(cf)
        writer.writerow(["Section", "Key", "Value"])
        for key, val in result.items():
            if isinstance(val, dict):
                for k, v in val.items():
                    writer.writerow([key, k, v])
            elif isinstance(val, list):
                for i, v in enumerate(val):
                    writer.writerow([key, f"{i}", str(v)])
            else:
                writer.writerow([key, "", val])

    return result


# 📥 Export analyzed data to CSV (after analysis is done)
@app.get("/export/csv")
async def export_csv():
    result = latest_report.get("csv")

    if not result:
        raise HTTPException(status_code=404, detail="No analysis data available")

    # Ensure that the file exists before returning it
    if not os.path.exists(result):
        raise HTTPException(status_code=404, detail="CSV file not found")

    return FileResponse(result)

# Root endpoint to serve the main page
@app.get("/")
async def root():
    return FileResponse("static/index.html")

# Result page endpoint
@app.get("/result", response_class=HTMLResponse)
async def result():
    return HTMLResponse(content=open("static/result.html").read())

#Configure CORS middleware to allow cross-origin requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all domains; for production, restrict to specific domains
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods like GET, POST, etc.
    allow_headers=["*"],  # Allows all headers
)
