"""
FastAPI routes for the CypherRay ML service.
"""

import os
import gc
import json
import tempfile
import traceback
from fastapi import APIRouter, File, UploadFile, HTTPException
from openai import OpenAI

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


@router.get("/", tags=["Root"])
async def root():
    """Root endpoint with API information."""
    return {
        "service": "CypherRay",
        "version": "2.0.0",
        "description": "AI-powered cryptographic binary analysis system",
        "endpoints": {
            "/analyze": "POST - Upload and analyze binary executable",
            "/health": "GET - Check service health",
            "/docs": "GET - API documentation"
        },
        "status": {
            "angr_available": check_angr_available(),
            "openai_configured": bool(os.getenv('OPENAI_API_KEY')),
            "anthropic_configured": bool(os.getenv('ANTHROPIC_API_KEY') or os.getenv('ANTRHOPIC_API_KEY'))
        }
    }


@router.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check():
    """Health check endpoint for monitoring and deployment platforms."""
    angr_available = check_angr_available()
    openai_key_present = bool(os.getenv('OPENAI_API_KEY'))
    anthropic_key_present = bool(os.getenv('ANTHROPIC_API_KEY') or os.getenv('ANTRHOPIC_API_KEY'))
    
    health_status = HealthResponse(
        status="healthy" if (angr_available and openai_key_present) else "degraded",
        angr_available=angr_available,
        openai_configured=openai_key_present,
        anthropic_configured=anthropic_key_present,
        service="CypherRay ML Service",
        version="2.0.0"
    )
    
    # Return 503 if critical dependencies are missing
    if not openai_key_present:
        raise HTTPException(
            status_code=503,
            detail="OpenAI API key not configured. Set OPENAI_API_KEY environment variable."
        )
    
    return health_status


@router.get("/cost-summary", tags=["Analytics"])
async def get_cost_summary():
    """
    Get cost summary and usage statistics from the orchestrator.
    Shows API costs by model, provider, token usage, and call statistics.
    """
    try:
        orchestrator = get_orchestrator()
        summary = orchestrator.get_cost_summary()
        
        return {
            "status": "success",
            "summary": summary
        }
    except Exception as e:
        logger.error(f"Failed to get cost summary: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get cost summary: {str(e)}")


@router.post("/quick-classify", tags=["Analysis"])
async def quick_classify(file: UploadFile = File(...)):
    """
    Quick classification endpoint using cheapest model (GPT-4o-mini).
    Determines if binary likely contains cryptographic code without deep analysis.
    
    Returns:
    - is_cryptographic: boolean
    - confidence: 0.0 to 1.0
    - reasoning: brief explanation
    - cost: API cost for this call
    - model_used: which model was used
    """
    orchestrator = get_orchestrator()
    
    # Read file
    file_content = await file.read()
    logger.info(f"Quick classification for: {file.filename} ({len(file_content)} bytes)")
    
    # Save to temp file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp_file:
        tmp_file.write(file_content)
        tmp_path = tmp_file.name
    
    try:
        # Run quick metadata extraction
        if check_angr_available():
            from src.tools.angr_metadata import angr_analyze_binary_metadata
            from src.tools.angr_strings import angr_analyze_strings
            
            metadata = angr_analyze_binary_metadata(tmp_path)
            strings_data = angr_analyze_strings(tmp_path)
            
            context = {
                "filename": file.filename,
                "size": len(file_content),
                "architecture": metadata.get("architecture", "unknown"),
                "crypto_strings": strings_data.get("crypto_related_strings", [])[:10]
            }
        else:
            context = {
                "filename": file.filename,
                "size": len(file_content)
            }
        
        query = """
Based on the binary metadata and strings, quickly classify if this binary likely contains cryptographic implementations.

Respond in JSON format:
{
  "is_cryptographic": true/false,
  "confidence": 0.0-1.0,
  "reasoning": "brief explanation",
  "indicators": ["list", "of", "indicators"]
}
"""
        
        # Use orchestrator for quick classification
        result = await orchestrator.analyze(
            query=query,
            context=context,
            analysis_type='quick_classify'
        )
        
        # Parse JSON response
        try:
            classification = json.loads(result['content'])
        except json.JSONDecodeError:
            # Try to extract JSON from markdown
            content = result['content']
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0].strip()
            classification = json.loads(content)
        
        return {
            "status": "success",
            "classification": classification,
            "metadata": {
                "model_used": result['model'],
                "provider": result['provider'],
                "cost": result['cost'],
                "duration": result['duration']
            }
        }
        
    except Exception as e:
        logger.error(f"Quick classification failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


@router.post("/analyze", tags=["Analysis"])
async def analyze_binary(file: UploadFile = File(...), force_deep: bool = False):
    """
    🚀 Analyze binary executable using intelligent multi-stage pipeline.
    
    This endpoint uses a cost-optimized 3-stage approach:
    1. Quick triage (GPT-4o-mini) - determines if binary is cryptographic
    2. Angr extraction - static analysis of binary 
    3. LLM synthesis (model selected based on complexity) - comprehensive analysis
    
    - **file**: Binary executable file
    - **force_deep**: Skip triage and force deep analysis (default: False)
    
    Returns comprehensive cryptographic analysis with:
    - Detected algorithms (AES, RSA, SHA, etc.)
    - Security vulnerabilities and recommendations
    - Protocol analysis (TLS, SSH, IPSec)
    - Library detection (OpenSSL, mbedTLS, custom)
    - Security score (0-10)
    - XAI explanations
    """
    pipeline = get_pipeline()
    
    # Read file
    file_content = await file.read()
    logger.info(f"Smart analysis for: {file.filename} ({len(file_content)} bytes)")
    
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
