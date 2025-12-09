"""
FastAPI routes for the CypherRay ML service.
"""

import os
import gc
import json
import tempfile
import traceback
from fastapi import APIRouter, File, UploadFile, HTTPException, Form

from src.api.models import AnalysisResponse, HealthResponse
from src.core.angr_tools import ANGR_TOOLS, ANGR_FUNCTION_MAP, check_angr_available
from src.models.multi_model_orchestrator import MultiModelOrchestrator
from src.core.analysis_pipeline import AnalysisPipeline
from src.utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter()

# Global orchestrator and pipeline instances (initialized on first use)
_orchestrator = None
_pipeline = None

def get_orchestrator() -> MultiModelOrchestrator:
    """Get or create the multi-model orchestrator instance (singleton)."""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = MultiModelOrchestrator(enable_caching=True)
        logger.info("Multi-Model Orchestrator initialized")
    return _orchestrator

def get_pipeline() -> AnalysisPipeline:
    """Get or create the analysis pipeline instance (singleton)."""
    global _pipeline
    if _pipeline is None:
        _pipeline = AnalysisPipeline(get_orchestrator())
        logger.info("Analysis Pipeline initialized")
    return _pipeline


@router.post("/analyze", tags=["Analysis"], 
             summary="Analyze Binary File",
             description="Upload a binary executable file for comprehensive cryptographic analysis")
async def analyze_binary(
    file: UploadFile = File(..., description="Binary executable file to analyze"),
    force_deep: bool = Form(False, description="Skip triage and force deep analysis (default: False)")
):
    """
    🚀 **Analyze Binary Executable for Cryptographic Implementations**
    
    Upload a binary file and receive comprehensive cryptographic analysis including:
    
    **Analysis Includes:**
    - 🔐 **Detected Algorithms**: AES, RSA, SHA, DES, RC4, ECC, etc.
    - 🛡️ **Security Vulnerabilities**: Weak keys, hardcoded secrets, insecure modes
    - 📡 **Protocol Detection**: TLS, SSH, IPSec, JWT, Kerberos, etc.
    - 📚 **Library Detection**: OpenSSL, mbedTLS, Bouncy Castle, custom implementations
    - 📊 **Security Score**: Overall rating (0-10)
    - 🔍 **Function Analysis**: Detailed crypto function breakdowns
    - 💡 **XAI Explanations**: Understandable security recommendations
    
    **Multi-Stage Pipeline:**
    1. ⚡ Quick Triage (if force_deep=False) - determines if binary contains crypto
    2. 🔬 Angr Static Analysis - extracts functions, strings, constants
    3. 🤖 AI-Powered Synthesis - comprehensive algorithm and vulnerability detection
    
    **Parameters:**
    - **file** (required): Binary executable file (ELF, PE, Mach-O, or raw binary)
    - **force_deep** (optional): Set to `true` to skip triage and force full analysis
    
    **Returns:**
    ```json
    {
      "status": "success",
      "analysis": {
        "algorithms": [...],
        "vulnerabilities": [...],
        "protocols": [...],
        "security_score": 7.5,
        "overall_assessment": "...",
        ...
      }
    }
    ```
    """
    pipeline = get_pipeline()
    
    # Read file
    file_content = await file.read()
    logger.info(f"Smart analysis for: {file.filename} ({len(file_content)} bytes) [force_deep={force_deep}]")
    
    if len(file_content) == 0:
        raise HTTPException(status_code=400, detail="Empty file uploaded")
    
    # Save to temp file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp_file:
        tmp_file.write(file_content)
        tmp_path = tmp_file.name
    
    try:
        # Run intelligent pipeline
        result = await pipeline.analyze_binary(
            binary_path=tmp_path,
            filename=file.filename,
            force_deep=force_deep
        )
        
        # Check if analysis was skipped
        if result.get('skipped'):
            return {
                "status": "skipped",
                "message": "Binary does not appear to contain cryptographic code",
                "details": result
            }
        
        return {
            "status": "success",
            "analysis": result
        }
        
    except Exception as e:
        logger.error(f"Smart analysis failed: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
        
        # Force garbage collection after analysis to free memory
        gc.collect()
        logger.debug("🧹 Garbage collection completed")
