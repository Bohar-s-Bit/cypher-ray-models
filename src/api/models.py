"""
Pydantic models for API requests and responses.
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any


# ==================== ALGORITHM MODELS ====================

class DetectedAlgorithm(BaseModel):
    """Detected cryptographic algorithm with enhanced metadata."""
    name: str = Field(..., description="Algorithm name (e.g., 'AES-128', 'RSA-2048')")
    type: str = Field(..., description="Type: symmetric, asymmetric, hash, encoding, kdf, mac, rng, proprietary")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score 0.0-1.0")
    evidence: List[str] = Field(default_factory=list, description="Evidence found (constants, patterns, strings)")
    functions: List[str] = Field(default_factory=list, description="Functions implementing this algorithm")
    locations: List[str] = Field(default_factory=list, description="Memory addresses (e.g., '0x401000')")
    is_proprietary: bool = Field(default=False, description="Whether this is a proprietary/custom implementation")
    standard_library: Optional[str] = Field(None, description="Matched library (e.g., 'OpenSSL', 'mbedTLS')")


# ==================== FUNCTION MODELS ====================

class FunctionAnalysis(BaseModel):
    """Analysis of a cryptographic function."""
    name: str = Field(..., description="Function name or 'sub_401000' if stripped")
    address: str = Field(..., description="Hex address (e.g., '0x401000')")
    crypto_operations: List[str] = Field(default_factory=list, description="Operations: xor, shift, substitute, etc.")
    explanation: str = Field(..., description="What this function does in crypto context")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Analysis confidence")
    related_algorithm: Optional[str] = Field(None, description="Which algorithm this function implements")


# ==================== PROTOCOL MODELS ====================

class DetectedProtocol(BaseModel):
    """Detected cryptographic protocol."""
    name: str = Field(..., description="Protocol name (e.g., 'TLS 1.2', 'SSH')")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Detection confidence")
    evidence: List[str] = Field(default_factory=list, description="Protocol indicators found")
    handshake_detected: bool = Field(default=False, description="Whether handshake pattern was found")
    key_exchange_method: Optional[str] = Field(None, description="Key exchange method used")
    cipher_suites: List[str] = Field(default_factory=list, description="Detected cipher suites")
    state_machine: Optional[str] = Field(None, description="Protocol state flow description")


class ProtocolAnalysis(BaseModel):
    """Protocol analysis results."""
    detected_protocols: List[DetectedProtocol] = Field(default_factory=list)


# ==================== VULNERABILITY MODELS ====================

class DeprecatedAlgorithm(BaseModel):
    """Deprecated algorithm detection."""
    algorithm: str = Field(..., description="Deprecated algorithm name")
    severity: str = Field(..., description="Severity: high, medium, low")
    reason: str = Field(..., description="Why it's deprecated")
    recommendation: str = Field(..., description="What to use instead")


class WeakConfiguration(BaseModel):
    """Weak cryptographic configuration."""
    issue: str = Field(..., description="Issue description")
    severity: str = Field(..., description="Severity level")
    location: str = Field(..., description="Function or address")
    fix: str = Field(..., description="How to fix")


class ImplementationIssue(BaseModel):
    """Implementation vulnerability."""
    issue: str = Field(..., description="Issue description")
    severity: str = Field(..., description="Severity level")
    cwe_id: Optional[str] = Field(None, description="CWE identifier (e.g., 'CWE-327')")
    description: str = Field(..., description="Detailed description")


class VulnerabilityAssessment(BaseModel):
    """Comprehensive vulnerability assessment."""
    deprecated_algorithms: List[DeprecatedAlgorithm] = Field(default_factory=list)
    weak_configurations: List[WeakConfiguration] = Field(default_factory=list)
    implementation_issues: List[ImplementationIssue] = Field(default_factory=list)
    overall_severity: str = Field(default="none", description="Overall severity: none, low, medium, high, critical")
    security_score: float = Field(default=10.0, ge=0.0, le=10.0, description="Security score 0-10")


# ==================== STRUCTURAL ANALYSIS ====================

class CodeComplexity(BaseModel):
    """Code complexity metrics."""
    cyclomatic_complexity: Optional[int] = Field(None, description="Cyclomatic complexity")
    function_count: int = Field(..., description="Total function count")
    crypto_function_ratio: float = Field(..., ge=0.0, le=1.0, description="Ratio of crypto functions")


class StructuralAnalysis(BaseModel):
    """Structural analysis of binary."""
    architecture_patterns: List[str] = Field(default_factory=list, description="Feistel, SPN, ARX, etc.")
    control_flow_indicators: List[str] = Field(default_factory=list, description="Control flow patterns")
    data_flow_patterns: List[str] = Field(default_factory=list, description="Data flow patterns")
    code_complexity: Optional[CodeComplexity] = Field(None)


# ==================== LIBRARY DETECTION ====================

class KnownLibrary(BaseModel):
    """Detected known cryptographic library."""
    name: str = Field(..., description="Library name (e.g., 'OpenSSL 1.1.1')")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Detection confidence")
    functions_matched: List[str] = Field(default_factory=list, description="Matched function names")
    version: Optional[str] = Field(None, description="Library version if detected")


class LibraryDetection(BaseModel):
    """Library detection results."""
    known_libraries: List[KnownLibrary] = Field(default_factory=list)
    is_custom_implementation: bool = Field(default=False, description="Whether this appears to be custom crypto")
    similarity_to_known: float = Field(default=0.0, ge=0.0, le=1.0, description="Similarity to known implementations")


# ==================== EXPLAINABILITY ====================

class Explainability(BaseModel):
    """Explainability and reasoning."""
    summary: str = Field(..., description="2-4 sentence overall conclusion")
    key_findings: List[str] = Field(default_factory=list, description="Important discoveries")
    confidence_reasoning: str = Field(..., description="Why these confidence scores were assigned")
    evidence_quality: str = Field(default="moderate", description="Evidence quality: strong, moderate, weak")
    limitations: List[str] = Field(default_factory=list, description="Analysis limitations or caveats")
    detailed_explanation: str = Field(..., description="Comprehensive XAI report with Angr citations")


# ==================== RECOMMENDATIONS ====================

class Recommendation(BaseModel):
    """Security or improvement recommendation."""
    type: str = Field(..., description="Type: security, performance, compliance")
    priority: str = Field(..., description="Priority: critical, high, medium, low")
    issue: str = Field(..., description="What the problem is")
    suggestion: str = Field(..., description="How to fix it")
    affected_functions: List[str] = Field(default_factory=list, description="Affected functions or addresses")


# ==================== FILE METADATA ====================

class FileMetadata(BaseModel):
    """Binary file metadata."""
    filename: str = Field(..., description="Original filename")
    size: int = Field(..., description="File size in bytes")
    architecture: str = Field(..., description="Architecture (e.g., 'ARM', 'x86_64')")
    file_type: str = Field(..., description="File type (e.g., 'ELF', 'PE', 'Mach-O')")
    md5: str = Field(..., description="MD5 hash")
    sha256: str = Field(..., description="SHA256 hash")
    entry_point: Optional[str] = Field(None, description="Entry point address")


# ==================== MAIN RESPONSE ====================

class EnhancedAnalysisResponse(BaseModel):
    """Complete enhanced analysis response."""
    file_metadata: FileMetadata
    detected_algorithms: List[DetectedAlgorithm] = Field(default_factory=list)
    function_analysis: List[FunctionAnalysis] = Field(default_factory=list)
    protocol_analysis: ProtocolAnalysis = Field(default_factory=ProtocolAnalysis)
    vulnerability_assessment: VulnerabilityAssessment = Field(default_factory=VulnerabilityAssessment)
    structural_analysis: StructuralAnalysis = Field(default_factory=StructuralAnalysis)
    library_detection: LibraryDetection = Field(default_factory=LibraryDetection)
    explainability: Explainability
    recommendations: List[Recommendation] = Field(default_factory=list)


# ==================== LEGACY MODELS (for backward compatibility) ====================

class CryptoAlgorithm(BaseModel):
    """Legacy algorithm model."""
    algorithm_name: str
    confidence_score: float
    algorithm_class: str
    structural_signature: Optional[str] = None


class AnalysisResponse(BaseModel):
    """Legacy analysis response."""
    file_metadata: Dict[str, Any]
    detected_algorithms: List[Dict[str, Any]]
    function_analyses: Optional[List[Dict[str, Any]]] = None
    vulnerability_assessment: Optional[Dict[str, Any]] = None
    overall_assessment: Optional[str] = None
    xai_explanation: Optional[str] = None


# ==================== HEALTH CHECK ====================

class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    angr_available: bool
    openai_configured: bool
    anthropic_configured: bool
    service: str
    version: str
