from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional
import openai
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

# Initialize OpenAI client
openai.api_key = os.getenv("OPENAI_API_KEY")

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
    
    # Read file content
    file_content = await file.read()
    
    if len(file_content) == 0:
        raise HTTPException(status_code=400, detail="Empty file uploaded")
    
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
        # Use the modern OpenAI v1.0+ API
        response = openai.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.2,
            max_tokens=4096
        )

        # Extract content using the new response structure
        content = response.choices[0].message.content
        analysis_json = json.loads(content)
        return AnalysisResponse(**analysis_json)

    except json.JSONDecodeError as jde:
        raise HTTPException(status_code=502, detail=f"LLM returned invalid JSON: {str(jde)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"LLM analysis failed: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
