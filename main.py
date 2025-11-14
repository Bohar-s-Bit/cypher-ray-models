from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional
import os
from dotenv import load_dotenv
import json
import base64

# Load environment variables
load_dotenv()

app = FastAPI(
    title="CypherRay - Cryptographic Binary Analysis System",
    description="AI-powered cryptographic algorithm detection and binary analysis",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Lazy-load OpenAI client for faster cold starts
client = None

def get_openai_client():
    global client
    if client is None:
        from openai import OpenAI
        client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    return client

# Response Models
class CryptoAlgorithm(BaseModel):
    algorithm_name: str = Field(..., description="Name of the detected cryptographic algorithm")
    confidence_score: float = Field(..., ge=0.0, le=1.0, description="Confidence score between 0.0 and 1.0")
    algorithm_class: str = Field(..., description="Class of algorithm (e.g., Symmetric, Asymmetric, Hash, Encoding)")
    structural_signature: Optional[str] = Field(None, description="Structural pattern matched (e.g., Feistel, Merkle-Damgård)")

class FileMetadata(BaseModel):
    file_type: str = Field(..., description="Detected file type and architecture")
    size_bytes: int = Field(..., description="File size in bytes")
    md5: str = Field(..., description="MD5 hash of the file")
    sha1: str = Field(..., description="SHA1 hash of the file")
    sha256: str = Field(..., description="SHA256 hash of the file")

class FunctionAnalysis(BaseModel):
    function_name: Optional[str] = Field(None, description="Name or identifier of the analyzed function")
    function_summary: str = Field(..., description="Plain-language summary of the function's purpose")
    semantic_tags: List[str] = Field(default_factory=list, description="Semantic tags describing the function")
    is_crypto: bool = Field(..., description="Whether the function performs cryptographic operations")
    confidence_score: float = Field(..., ge=0.0, le=1.0, description="Confidence in the analysis")
    data_flow_pattern: Optional[str] = Field(None, description="Detected data flow graph pattern")

class VulnerabilityAssessment(BaseModel):
    has_vulnerabilities: bool = Field(..., description="Whether vulnerabilities were detected")
    severity: Optional[str] = Field(None, description="Severity level: Low, Medium, High, Critical")
    vulnerabilities: List[str] = Field(default_factory=list, description="List of identified vulnerabilities")
    recommendations: List[str] = Field(default_factory=list, description="Security recommendations")

class AnalysisResponse(BaseModel):
    file_metadata: FileMetadata
    detected_algorithms: List[CryptoAlgorithm]
    function_analyses: List[FunctionAnalysis]
    vulnerability_assessment: VulnerabilityAssessment
    overall_assessment: str = Field(..., description="High-level conclusion about the binary")
    xai_explanation: str = Field(..., description="Explainability analysis from structural and semantic models")

# API Endpoints
@app.get("/")
@app.head("/")  # Add HEAD method for health checks
async def root():
    """Root endpoint with API information."""
    return {
        "service": "CypherRay",
        "version": "1.0.0",
        "description": "AI-powered cryptographic binary analysis system",
        "endpoints": {
            "/analyze": "POST - Upload and analyze binary executable",
            "/health": "GET - Check service health"
        }
    }

@app.get("/health")
@app.head("/health")  # Add HEAD method for health checks
async def health_check():
    """Health check endpoint for monitoring and load balancers."""
    # Check if OpenAI API key is configured
    api_key_configured = bool(os.getenv("OPENAI_API_KEY"))
    
    return {
        "status": "healthy" if api_key_configured else "degraded",
        "service": "CypherRay ML Analysis",
        "version": "1.0.0",
        "openai_configured": api_key_configured,
        "ready": api_key_configured
    }
@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_binary(file: UploadFile = File(...)):
    """
    Analyze a binary executable for cryptographic algorithms and vulnerabilities.
    
    - **file**: Binary executable file (.exe, Mach-O, ELF, etc.)
    
    Returns comprehensive analysis including:
    - Detected cryptographic algorithms with confidence scores
    - File metadata and hashes
    - Function-level analysis with semantic explanations
    - Structural analysis (DFG pattern matching)
    - Vulnerability assessment
    - XAI explanations
    """
    
    try:
        # Read file content
        file_content = await file.read()
        
        if len(file_content) == 0:
            raise HTTPException(status_code=400, detail="Empty file uploaded")
        
        # Limit file size to 100MB
        if len(file_content) > 100 * 1024 * 1024:
            raise HTTPException(status_code=413, detail="File too large. Maximum size: 100MB")
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error reading file: {str(e)}")
    
    # Encode binary to base64 for LLM
    encoded_binary = base64.b64encode(file_content).decode('utf-8')
    
    # Load system prompt
    prompt_path = os.path.join("prompts", "system.md")
    try:
        with open(prompt_path, "r", encoding="utf-8") as f:
            system_prompt = f.read()
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="System prompt file not found")
    
    # Create user prompt - LLM will handle ALL analysis including hashes and file detection
    user_prompt = f"""
Analyze the following binary executable:

**Filename:** {file.filename}
**Size:** {len(file_content)} bytes

**Binary Content (Base64 encoded):** 
{encoded_binary}

Please provide a comprehensive cryptographic analysis following the JSON schema specified in the system prompt.
You MUST calculate the MD5, SHA1, and SHA256 hashes of this binary.
You MUST detect the file type and architecture.
You MUST perform all structural analysis, semantic analysis, algorithm detection, and vulnerability assessment.
"""
    
    try:
        # Get OpenAI client (lazy-loaded for faster cold starts)
        openai_client = get_openai_client()
        
        # Use the modern OpenAI v1.0+ API with proper client
        # Using gpt-4-turbo-preview which supports JSON mode
        response = openai_client.chat.completions.create(
            model="gpt-4-turbo-preview",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.2,
            max_tokens=4096,
            response_format={"type": "json_object"}  # Ensure JSON response
        )

        # Extract content using the new response structure
        content = response.choices[0].message.content
        
        if not content:
            raise HTTPException(status_code=502, detail="LLM returned empty response")
        
        # Parse JSON
        try:
            analysis_json = json.loads(content)
        except json.JSONDecodeError as jde:
            print(f"Invalid JSON from LLM: {content[:500]}...")
            raise HTTPException(status_code=502, detail=f"LLM returned invalid JSON: {str(jde)}")
        
        # Validate and return
        return AnalysisResponse(**analysis_json)

    except HTTPException:
        raise
    except Exception as e:
        # Handle any OpenAI-related errors
        error_msg = str(e)
        print(f"Unexpected error during analysis: {error_msg}")
        
        if "authentication" in error_msg.lower() or "api_key" in error_msg.lower():
            raise HTTPException(status_code=401, detail="OpenAI API authentication failed. Check your API key.")
        elif "rate" in error_msg.lower() and "limit" in error_msg.lower():
            raise HTTPException(status_code=429, detail="OpenAI API rate limit exceeded. Please try again later.")
        elif "openai" in error_msg.lower() or "api" in error_msg.lower():
            raise HTTPException(status_code=502, detail=f"OpenAI API error: {error_msg}")
        else:
            raise HTTPException(status_code=500, detail=f"Analysis failed: {error_msg}")

if __name__ == "__main__":
    import uvicorn
    # Use PORT from environment variable (for Render/Railway) or default to 5000 (local)
    port = int(os.getenv("PORT", 5000))
    print("🚀 Starting CypherRay ML Analysis Service...")
    print(f"📍 Server: http://0.0.0.0:{port}")
    print(f"📊 Health check: http://localhost:{port}/health")
    print(f"🔍 Analysis endpoint: http://localhost:{port}/analyze")
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
