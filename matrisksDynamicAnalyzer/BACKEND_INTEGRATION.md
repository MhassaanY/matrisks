# Backend Integration Guide (Phase 2)

This guide shows how to integrate the dynamic analyzer with the Matrisks backend.

## Step 1: Add Dynamic Analysis Route

Create or update `matrisks-backend/app/routers/analysis.py`:

```python
from fastapi import APIRouter, UploadFile, File, BackgroundTasks, HTTPException
from pathlib import Path
import sys
import os

# Add dynamic_analyzer to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "dynamic_analyzer"))

from core.orchestrator import DynamicAnalysisOrchestrator

router = APIRouter(prefix="/analysis", tags=["analysis"])

# Configuration
DYNAMIC_ANALYZER_CONFIG = {
    "avd_name": "Pixel_5_API_30",
    "output_dir": "/tmp/matrisks_dynamic_results",
    "frida_server_path": os.environ.get("FRIDA_SERVER_PATH"),
    "analysis_duration": 60
}


@router.post("/dynamic")
async def analyze_apk_dynamic(
    background_tasks: BackgroundTasks,
    apk_file: UploadFile = File(...)
):
    """
    Perform dynamic analysis on an uploaded APK
    """
    # Save uploaded file
    temp_dir = Path("/tmp/matrisks_uploads")
    temp_dir.mkdir(parents=True, exist_ok=True)
    
    apk_path = temp_dir / apk_file.filename
    with open(apk_path, "wb") as f:
        content = await apk_file.read()
        f.write(content)
    
    # Create orchestrator
    orchestrator = DynamicAnalysisOrchestrator(
        avd_name=DYNAMIC_ANALYZER_CONFIG["avd_name"],
        output_dir=DYNAMIC_ANALYZER_CONFIG["output_dir"],
        frida_server_path=DYNAMIC_ANALYZER_CONFIG["frida_server_path"]
    )
    
    # Run analysis (synchronous for now)
    try:
        results = orchestrator.analyze_apk(
            apk_path=str(apk_path),
            analysis_duration=DYNAMIC_ANALYZER_CONFIG["analysis_duration"]
        )
        
        if not results["success"]:
            raise HTTPException(status_code=500, detail=results.get("error"))
        
        # Clean up uploaded file
        apk_path.unlink()
        
        return {
            "success": True,
            "package_name": results.get("package_name"),
            "statistics": results.get("statistics"),
            "sensitive_behaviors": results.get("sensitive_behaviors"),
            "output_files": {
                "api_calls": results.get("api_calls_file"),
                "network": results.get("network_file")
            }
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/dynamic/status")
async def get_analysis_status():
    """
    Get status of dynamic analysis service
    """
    from core.orchestrator import DynamicAnalysisOrchestrator
    
    orchestrator = DynamicAnalysisOrchestrator(
        avd_name=DYNAMIC_ANALYZER_CONFIG["avd_name"],
        output_dir="/tmp"
    )
    
    avds = orchestrator.list_available_avds()
    
    return {
        "available": len(avds) > 0,
        "avds": avds,
        "configured_avd": DYNAMIC_ANALYZER_CONFIG["avd_name"]
    }
```

## Step 2: Update Main App

Add the route to `matrisks-backend/app/main.py`:

```python
from app.routers import analysis  # Add this import

app.include_router(analysis.router)
```

## Step 3: Add Dependencies

Update `matrisks-backend/requirements.txt`:

```
frida==16.1.4
frida-tools==12.3.0
androguard==3.4.0a1
pyyaml==6.0.1
psutil==5.9.5
```

## Step 4: Environment Variables

Add to `.env` or environment:

```bash
ANDROID_SDK_ROOT=/path/to/Android/Sdk
FRIDA_SERVER_PATH=/path/to/frida-server
```

## Step 5: Frontend Integration

Add dynamic analysis button to frontend (`matrisks-frontend/src/components/AnalysisForm.jsx`):

```jsx
import { useState } from 'react';
import axios from 'axios';

function DynamicAnalysisButton({ apkFile }) {
  const [analyzing, setAnalyzing] = useState(false);
  const [results, setResults] = useState(null);

  const runDynamicAnalysis = async () => {
    setAnalyzing(true);
    
    const formData = new FormData();
    formData.append('apk_file', apkFile);
    
    try {
      const response = await axios.post(
        'http://localhost:8000/analysis/dynamic',
        formData,
        {
          headers: { 'Content-Type': 'multipart/form-data' },
          timeout: 300000 // 5 minute timeout
        }
      );
      
      setResults(response.data);
      alert(`Dynamic analysis complete! Found ${response.data.statistics.total_calls} API calls`);
    } catch (error) {
      alert(`Dynamic analysis failed: ${error.message}`);
    } finally {
      setAnalyzing(false);
    }
  };

  return (
    <div>
      <button 
        onClick={runDynamicAnalysis} 
        disabled={analyzing || !apkFile}
        className="btn btn-primary"
      >
        {analyzing ? 'Analyzing...' : 'Run Dynamic Analysis'}
      </button>
      
      {results && (
        <div className="results">
          <h3>Dynamic Analysis Results</h3>
          <p>Package: {results.package_name}</p>
          <p>API Calls: {results.statistics.total_calls}</p>
          <h4>Sensitive Behaviors:</h4>
          <ul>
            {Object.entries(results.sensitive_behaviors).map(([key, value]) => (
              <li key={key}>{key}: {value.length} events</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

export default DynamicAnalysisButton;
```

## Step 6: Async Processing (Recommended)

For production, use background tasks to avoid timeout:

```python
from fastapi import BackgroundTasks
from app.database import SessionLocal
from app.models import DynamicAnalysisResult

def run_dynamic_analysis_background(scan_id: int, apk_path: str):
    """Background task for dynamic analysis"""
    orchestrator = DynamicAnalysisOrchestrator(...)
    results = orchestrator.analyze_apk(apk_path)
    
    # Save to database
    db = SessionLocal()
    analysis = DynamicAnalysisResult(
        scan_id=scan_id,
        success=results["success"],
        api_calls=results["statistics"]["total_calls"],
        sensitive_behaviors=results["sensitive_behaviors"]
    )
    db.add(analysis)
    db.commit()
    db.close()

@router.post("/dynamic/async")
async def analyze_apk_dynamic_async(
    background_tasks: BackgroundTasks,
    apk_file: UploadFile = File(...)
):
    """Start dynamic analysis in background"""
    scan_id = create_scan_record()
    
    # Save file
    apk_path = save_upload(apk_file)
    
    # Queue background task
    background_tasks.add_task(
        run_dynamic_analysis_background,
        scan_id,
        str(apk_path)
    )
    
    return {
        "scan_id": scan_id,
        "status": "queued",
        "message": "Dynamic analysis started in background"
    }

@router.get("/dynamic/results/{scan_id}")
async def get_dynamic_results(scan_id: int):
    """Get dynamic analysis results by scan ID"""
    db = SessionLocal()
    result = db.query(DynamicAnalysisResult).filter_by(scan_id=scan_id).first()
    
    if not result:
        raise HTTPException(status_code=404, detail="Results not found")
    
    return result
```

## Step 7: Database Schema

Add to `matrisks-backend/app/models.py`:

```python
class DynamicAnalysisResult(Base):
    __tablename__ = "dynamic_analysis_results"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    created_at = Column(DateTime, default=datetime.utcnow)
    
    success = Column(Boolean)
    package_name = Column(String)
    api_calls = Column(Integer)
    duration = Column(Float)
    
    # JSON fields
    statistics = Column(JSON)
    sensitive_behaviors = Column(JSON)
    
    # File paths
    api_calls_file = Column(String)
    network_file = Column(String)
    
    scan = relationship("Scan", back_populates="dynamic_results")
```

## Testing the Integration

```bash
# Start backend
cd matrisks-backend
source venv/bin/activate
uvicorn app.main:app --reload

# Test endpoint
curl -X POST http://localhost:8000/analysis/dynamic \
  -F "apk_file=@test.apk" \
  -H "Content-Type: multipart/form-data"

# Check status
curl http://localhost:8000/analysis/dynamic/status
```

## Production Considerations

1. **Scalability**: Use Celery for distributed task queue
2. **Resource Limits**: One emulator per analysis = high resource usage
3. **Timeouts**: Set appropriate timeouts (5-10 minutes per APK)
4. **Concurrency**: Limit concurrent analyses (recommend max 2-3)
5. **Storage**: Archive old analysis results
6. **Security**: Sanitize file uploads, validate APK format
7. **Monitoring**: Track emulator health, cleanup failed analyses

## Architecture Diagram

```
Frontend (React)
    ↓
Backend (FastAPI)
    ↓
Dynamic Analyzer Module
    ↓
   ┌──────────────┐
   │ Orchestrator │
   └──────────────┘
         ↓
    ┌────┴────┐
    ↓         ↓
Emulator   Frida
    ↓         ↓
  APK ←→  Hooks
    ↓
Collectors
    ↓
  JSON Files
    ↓
Database
```
