from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import openai
import os
from dotenv import load_dotenv
import json
import base64
import hashlib
import tempfile
import logging
import logfire
import traceback

# Try to import angr - may fail in production environments
try:
    import angr
    import claripy
    ANGR_AVAILABLE = True
    print("✅ Angr loaded successfully")
except ImportError as e:
    ANGR_AVAILABLE = False
    print(f"⚠️ Angr not available: {e}")
    print("⚠️ Binary analysis will use fallback mode")

# Load environment variables
load_dotenv()

# Check critical environment variables
openai_api_key = os.getenv('OPENAI_API_KEY')
if not openai_api_key:
    print("❌ ERROR: OPENAI_API_KEY not found in environment variables!")
    print("Please set OPENAI_API_KEY in your Render dashboard")
else:
    print("✅ OpenAI API key found")
    openai.api_key = openai_api_key

# Configure Logfire - use environment variables for production
try:
    logfire_token = os.getenv('LOGFIRE_TOKEN')
    if logfire_token:
        # Production: Use token from environment
        logfire.configure(
            token=logfire_token,
            inspect_arguments=False
        )
        print("✅ Logfire configured successfully")
    else:
        # Local development: Disable sending to Logfire
        logfire.configure(inspect_arguments=False, send_to_logfire=False)
        print("⚠️ Logfire running in local mode (not sending data)")
except Exception as e:
    print(f"⚠️ Logfire configuration skipped: {e}")
    # Continue without Logfire if authentication fails
    pass

# Suppress Angr's verbose logging
logging.getLogger('angr').setLevel(logging.CRITICAL)
logging.getLogger('cle').setLevel(logging.CRITICAL)
logging.getLogger('pyvex').setLevel(logging.CRITICAL)
logging.getLogger('cle.backends.macho').setLevel(logging.CRITICAL)

# ============================================================================
# ANGR TOOL FUNCTIONS - Called by LLM via Function Calling
# ============================================================================

def angr_analyze_binary_metadata(binary_path: str) -> Dict[str, Any]:
    """
    Extract basic metadata from binary using Angr.
    Returns file type, architecture, entry point, and cryptographic hashes.
    """
    try:
        if not ANGR_AVAILABLE:
            return {"error": "Angr is not available in this environment. Please check server logs."}
        
        # Calculate hashes
        with open(binary_path, 'rb') as f:
            content = f.read()
            md5_hash = hashlib.md5(content).hexdigest()
            sha1_hash = hashlib.sha1(content).hexdigest()
            sha256_hash = hashlib.sha256(content).hexdigest()
        
        # Load binary with Angr
        project = angr.Project(binary_path, auto_load_libs=False)
        
        return {
            "file_type": f"{project.loader.main_object.os} {project.arch.name}",
            "architecture": str(project.arch.name),
            "size_bytes": os.path.getsize(binary_path),
            "entry_point": hex(project.entry),
            "md5": md5_hash,
            "sha1": sha1_hash,
            "sha256": sha256_hash,
            "endianness": project.arch.memory_endness,
            "bits": project.arch.bits
        }
    except Exception as e:
        return {"error": f"Failed to analyze metadata: {str(e)}"}

def angr_extract_functions(binary_path: str, limit: int = 50) -> Dict[str, Any]:
    """
    Extract function information from binary using Angr's CFG analysis.
    Returns function addresses, names, and basic block counts.
    """
    try:
        if not ANGR_AVAILABLE:
            return {"error": "Angr is not available in this environment"}
        
        project = angr.Project(binary_path, auto_load_libs=False)
        cfg = project.analyses.CFGFast()
        
        functions = []
        for addr, func in list(cfg.functions.items())[:limit]:
            functions.append({
                "address": hex(addr),
                "name": func.name,
                "size": func.size,
                "num_blocks": len(list(func.blocks)),
                "is_simprocedure": func.is_simprocedure,
                "is_plt": func.is_plt
            })
        
        return {
            "total_functions": len(cfg.functions),
            "functions": functions,
            "analyzed_count": len(functions)
        }
    except Exception as e:
        return {"error": f"Failed to extract functions: {str(e)}"}

def angr_analyze_strings(binary_path: str) -> Dict[str, Any]:
    """
    Extract readable strings from binary that may indicate cryptographic operations.
    """
    try:
        if not ANGR_AVAILABLE:
            return {"error": "Angr is not available in this environment"}
        
        project = angr.Project(binary_path, auto_load_libs=False)
        
        crypto_keywords = [
            'aes', 'rsa', 'des', 'sha', 'md5', 'encrypt', 'decrypt', 'cipher',
            'key', 'hash', 'crypto', 'ssl', 'tls', 'openssl', 'blowfish',
            'rc4', 'chacha', 'curve25519', 'ecdsa', 'pbkdf', 'bcrypt'
        ]
        
        # Extract strings from binary sections
        interesting_strings = []
        for section_name, section in project.loader.main_object.sections_map.items():
            try:
                data = project.loader.memory.load(section.vaddr, section.memsize)
                # Simple string extraction (printable ASCII sequences)
                current_string = ""
                for byte in data:
                    if 32 <= byte <= 126:  # Printable ASCII
                        current_string += chr(byte)
                    else:
                        if len(current_string) >= 4:
                            string_lower = current_string.lower()
                            if any(keyword in string_lower for keyword in crypto_keywords):
                                interesting_strings.append({
                                    "string": current_string,
                                    "section": section_name
                                })
                        current_string = ""
            except:
                continue
        
        return {
            "crypto_related_strings": interesting_strings[:100],  # Limit to first 100
            "total_found": len(interesting_strings)
        }
    except Exception as e:
        return {"error": f"Failed to analyze strings: {str(e)}"}

def angr_analyze_function_dataflow(binary_path: str, function_address: str, max_depth: int = 20) -> Dict[str, Any]:
    """
    Analyze data flow patterns in a specific function to detect crypto operations.
    Looks for characteristic patterns like XOR loops, rotations, S-box lookups.
    """
    try:
        if not ANGR_AVAILABLE:
            return {"error": "Angr is not available in this environment"}
        
        project = angr.Project(binary_path, auto_load_libs=False)
        cfg = project.analyses.CFGFast()
        
        # Convert address from hex string
        addr = int(function_address, 16)
        
        if addr not in cfg.functions:
            return {"error": f"Function at {function_address} not found"}
        
        func = cfg.functions[addr]
        
        # Analyze basic blocks for crypto patterns
        patterns_detected = []
        
        for block in list(func.blocks)[:max_depth]:
            try:
                # Get VEX IR for the block
                vex_block = project.factory.block(block.addr).vex
                
                # Look for XOR operations (common in crypto)
                xor_count = sum(1 for stmt in vex_block.statements if hasattr(stmt, 'op') and 'Xor' in str(stmt.op))
                if xor_count > 3:
                    patterns_detected.append(f"Multiple XOR operations ({xor_count}) at {hex(block.addr)} - potential XOR cipher")
                
                # Look for rotation operations (common in ARX ciphers)
                rot_count = sum(1 for stmt in vex_block.statements if hasattr(stmt, 'op') and ('Shl' in str(stmt.op) or 'Shr' in str(stmt.op)))
                if rot_count > 2:
                    patterns_detected.append(f"Rotation operations ({rot_count}) at {hex(block.addr)} - potential ARX structure")
                
                # Look for array indexing (S-box lookups)
                load_count = sum(1 for stmt in vex_block.statements if hasattr(stmt, 'tag') and 'Ist_WrTmp' in str(stmt.tag))
                if load_count > 5:
                    patterns_detected.append(f"Multiple table lookups ({load_count}) at {hex(block.addr)} - potential S-box operations")
                    
            except:
                continue
        
        return {
            "function_name": func.name,
            "function_address": hex(addr),
            "num_blocks_analyzed": min(len(list(func.blocks)), max_depth),
            "patterns_detected": patterns_detected,
            "function_size": func.size
        }
    except Exception as e:
        return {"error": f"Failed to analyze function dataflow: {str(e)}"}

def angr_detect_crypto_constants(binary_path: str) -> Dict[str, Any]:
    """
    Search for known cryptographic constants in the binary
    (e.g., AES S-box values, SHA round constants, etc.)
    """
    try:
        if not ANGR_AVAILABLE:
            return {"error": "Angr is not available in this environment"}
        
        project = angr.Project(binary_path, auto_load_libs=False)
        
        # Known crypto constants
        crypto_constants = {
            "AES_SBOX_FIRST_BYTES": bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b]),
            "SHA256_K_FIRST": bytes.fromhex('428a2f98'),
            "SHA1_INIT_H0": bytes.fromhex('67452301'),
            "MD5_INIT_A": bytes.fromhex('67452301'),
            "DES_IP_TABLE_START": bytes([58, 50, 42, 34, 26, 18]),
        }
        
        detected_constants = []
        
        # Search through binary sections
        for const_name, const_bytes in crypto_constants.items():
            for section_name, section in project.loader.main_object.sections_map.items():
                try:
                    data = project.loader.memory.load(section.vaddr, section.memsize)
                    if const_bytes in data:
                        offset = data.find(const_bytes)
                        detected_constants.append({
                            "constant_name": const_name,
                            "section": section_name,
                            "offset": hex(section.vaddr + offset)
                        })
                except:
                    continue
        
        return {
            "detected_constants": detected_constants,
            "total_found": len(detected_constants)
        }
    except Exception as e:
        return {"error": f"Failed to detect crypto constants: {str(e)}"}

# Tool definitions for OpenAI function calling
ANGR_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "angr_analyze_binary_metadata",
            "description": "Extract basic metadata from binary including file type, architecture, hashes (MD5, SHA1, SHA256), entry point, and endianness. Always call this first.",
            "parameters": {
                "type": "object",
                "properties": {
                    "binary_path": {
                        "type": "string",
                        "description": "Path to the binary file to analyze"
                    }
                },
                "required": ["binary_path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "angr_extract_functions",
            "description": "Extract function information including addresses, names, sizes, and basic block counts. Useful for identifying functions to analyze further.",
            "parameters": {
                "type": "object",
                "properties": {
                    "binary_path": {
                        "type": "string",
                        "description": "Path to the binary file"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of functions to return (default: 50)",
                        "default": 50
                    }
                },
                "required": ["binary_path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "angr_analyze_strings",
            "description": "Extract cryptography-related strings from the binary that may indicate what algorithms are implemented.",
            "parameters": {
                "type": "object",
                "properties": {
                    "binary_path": {
                        "type": "string",
                        "description": "Path to the binary file"
                    }
                },
                "required": ["binary_path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "angr_analyze_function_dataflow",
            "description": "Analyze data flow patterns in a specific function to detect cryptographic operation patterns (XOR loops, rotations, S-box lookups). Call this on suspicious functions.",
            "parameters": {
                "type": "object",
                "properties": {
                    "binary_path": {
                        "type": "string",
                        "description": "Path to the binary file"
                    },
                    "function_address": {
                        "type": "string",
                        "description": "Hexadecimal address of the function to analyze (e.g., '0x401000')"
                    },
                    "max_depth": {
                        "type": "integer",
                        "description": "Maximum number of basic blocks to analyze (default: 20)",
                        "default": 20
                    }
                },
                "required": ["binary_path", "function_address"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "angr_detect_crypto_constants",
            "description": "Search for known cryptographic constants (AES S-box, SHA constants, etc.) in the binary to identify specific algorithms.",
            "parameters": {
                "type": "object",
                "properties": {
                    "binary_path": {
                        "type": "string",
                        "description": "Path to the binary file"
                    }
                },
                "required": ["binary_path"]
            }
        }
    }
]

# Map function names to actual Python functions
ANGR_FUNCTION_MAP = {
    "angr_analyze_binary_metadata": angr_analyze_binary_metadata,
    "angr_extract_functions": angr_extract_functions,
    "angr_analyze_strings": angr_analyze_strings,
    "angr_analyze_function_dataflow": angr_analyze_function_dataflow,
    "angr_detect_crypto_constants": angr_detect_crypto_constants
}

app = FastAPI(
    title="CypherRay - Cryptographic Binary Analysis System",
    description="AI-powered cryptographic algorithm detection and binary analysis",
    version="1.0.0"
)

# Instrument FastAPI with Logfire
logfire.instrument_fastapi(app)

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
        },
        "status": {
            "angr_available": ANGR_AVAILABLE,
            "openai_configured": bool(os.getenv('OPENAI_API_KEY'))
        }
    }

@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring and deployment platforms."""
    openai_key_present = bool(os.getenv('OPENAI_API_KEY'))
    
    health_status = {
        "status": "healthy" if (ANGR_AVAILABLE and openai_key_present) else "degraded",
        "angr_available": ANGR_AVAILABLE,
        "openai_configured": openai_key_present,
        "service": "CypherRay ML Service",
        "version": "1.0.0"
    }
    
    # Return 503 if critical dependencies are missing
    if not openai_key_present:
        raise HTTPException(
            status_code=503,
            detail="OpenAI API key not configured. Set OPENAI_API_KEY environment variable."
        )
    
    return health_status
@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_binary(file: UploadFile = File(...)):
    """
    Analyze a binary executable for cryptographic algorithms and vulnerabilities.
    Uses Angr for binary analysis with LLM orchestration via function calling.
    
    - **file**: Binary executable file (.exe, Mach-O, ELF, etc.)
    
    Returns comprehensive analysis including:
    - Detected cryptographic algorithms with confidence scores
    - File metadata and hashes
    - Function-level analysis with semantic explanations
    - Structural analysis (DFG pattern matching)
    - Vulnerability assessment
    - XAI explanations
    """
    
    # Check if OpenAI is configured
    if not os.getenv('OPENAI_API_KEY'):
        raise HTTPException(
            status_code=503,
            detail="OpenAI API key not configured. Please contact administrator."
        )
    
    with logfire.span('analyze_binary', filename=file.filename):
        # Read file content
        file_content = await file.read()
        logfire.info('File uploaded', filename=file.filename, size_bytes=len(file_content))
    
    if len(file_content) == 0:
        raise HTTPException(status_code=400, detail="Empty file uploaded")
    
    # Save binary to temporary file for Angr analysis
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp_file:
        tmp_file.write(file_content)
        tmp_path = tmp_file.name
    
    try:
        # Load system prompt
        prompt_path = os.path.join("prompts", "system.md")
        try:
            if not os.path.exists(prompt_path):
                # Log current directory and files for debugging
                cwd = os.getcwd()
                files = os.listdir(cwd)
                print(f"ERROR: Prompt file not found at {prompt_path}")
                print(f"Current directory: {cwd}")
                print(f"Files in current directory: {files}")
                if os.path.exists('prompts'):
                    print(f"Files in prompts directory: {os.listdir('prompts')}")
                raise FileNotFoundError(f"System prompt file not found at {prompt_path}")
            
            with open(prompt_path, "r", encoding="utf-8") as f:
                system_prompt = f.read()
                print(f"✅ Loaded system prompt ({len(system_prompt)} characters)")
        except FileNotFoundError as fnf:
            logfire.error('Prompt file not found', path=prompt_path, error=str(fnf))
            raise HTTPException(status_code=500, detail=f"System prompt file not found: {prompt_path}")
        
        # Initial user prompt - instruct LLM to use Angr tools
        user_prompt = f"""
Analyze the binary executable: **{file.filename}** ({len(file_content)} bytes)

The binary has been saved to: {tmp_path}

You MUST use the available Angr tools to analyze this binary. Follow this process:

1. Call `angr_analyze_binary_metadata` to get file metadata and hashes
2. Call `angr_extract_functions` to get function list
3. Call `angr_analyze_strings` to find crypto-related strings
4. Call `angr_detect_crypto_constants` to find known crypto constants
5. Call `angr_analyze_function_dataflow` on suspicious functions to detect crypto patterns

Based on the Angr analysis results, provide a comprehensive cryptographic analysis following the JSON schema.
"""
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
        
        max_iterations = 10
        iteration = 0
        
        # Iterative function calling loop
        while iteration < max_iterations:
            iteration += 1
            
            response = openai.chat.completions.create(
                model="gpt-4o",
                messages=messages,
                tools=ANGR_TOOLS,
                tool_choice="auto",
                temperature=0.2,
                max_tokens=2048
            )
            
            assistant_message = response.choices[0].message
            messages.append(assistant_message)
            
            # Check if LLM wants to call tools
            if assistant_message.tool_calls:
                # Execute each tool call
                for tool_call in assistant_message.tool_calls:
                    function_name = tool_call.function.name
                    function_args = json.loads(tool_call.function.arguments)
                    
                    # Execute the Angr function
                    if function_name in ANGR_FUNCTION_MAP:
                        with logfire.span(f'angr_tool_{function_name}', **function_args):
                            function_to_call = ANGR_FUNCTION_MAP[function_name]
                            function_result = function_to_call(**function_args)
                            logfire.info(f'{function_name} completed', result_keys=list(function_result.keys()))
                        
                        # Add function result to messages
                        messages.append({
                            "role": "tool",
                            "tool_call_id": tool_call.id,
                            "name": function_name,
                            "content": json.dumps(function_result)
                        })
            else:
                # No more tool calls - LLM should have final analysis
                if assistant_message.content:
                    try:
                        # Log what we received from LLM for debugging
                        content = assistant_message.content
                        print(f"📝 LLM Response (first 500 chars): {content[:500]}")
                        logfire.info('LLM response received', content_length=len(content), content_preview=content[:200])
                        
                        analysis_json = json.loads(content)
                        logfire.info('Analysis completed successfully', 
                                   num_algorithms=len(analysis_json.get('detected_algorithms', [])),
                                   has_vulnerabilities=analysis_json.get('vulnerability_assessment', {}).get('has_vulnerabilities', False))
                        return AnalysisResponse(**analysis_json)
                    except json.JSONDecodeError as jde:
                        # Maybe LLM wrapped JSON in markdown
                        print(f"⚠️ First JSON parse failed: {str(jde)}")
                        print(f"📝 Full content: {content}")
                        
                        if "```json" in content:
                            print("🔄 Trying to extract JSON from markdown...")
                            content = content.split("```json")[1].split("```")[0].strip()
                            print(f"📝 Extracted content (first 500 chars): {content[:500]}")
                        
                        # Try parsing again
                        try:
                            analysis_json = json.loads(content)
                            logfire.info('Analysis completed successfully (markdown wrapped)', 
                                       num_algorithms=len(analysis_json.get('detected_algorithms', [])))
                            return AnalysisResponse(**analysis_json)
                        except json.JSONDecodeError as jde2:
                            print(f"❌ Second JSON parse also failed: {str(jde2)}")
                            print(f"📝 Content that failed: {content[:1000]}")
                            raise
                else:
                    logfire.error('LLM did not return analysis content')
                    raise HTTPException(status_code=502, detail="LLM did not return analysis")
        
        logfire.error('Max iterations reached', iterations=max_iterations)
        raise HTTPException(status_code=500, detail="Max iterations reached without completion")
        
    except json.JSONDecodeError as jde:
        error_details = traceback.format_exc()
        logfire.error('JSON decode error', error=str(jde), traceback=error_details)
        print(f"JSON DECODE ERROR: {str(jde)}")
        print(error_details)
        raise HTTPException(status_code=502, detail=f"LLM returned invalid JSON: {str(jde)}")
    except HTTPException as he:
        # Re-raise HTTP exceptions (like missing API key)
        raise he
    except Exception as e:
        error_details = traceback.format_exc()
        logfire.error('Analysis failed', error=str(e), error_type=type(e).__name__, traceback=error_details)
        print(f"ANALYSIS ERROR ({type(e).__name__}): {str(e)}")
        print(error_details)
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
    finally:
        # Clean up temporary file
        try:
            os.unlink(tmp_path)
        except:
            pass

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)
