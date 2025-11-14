# CypherRay - AI-Powered Cryptographic Binary Analysis System

CypherRay is an advanced system that uses Large Language Models (LLMs) to analyze binary executables and detect cryptographic algorithms, security vulnerabilities, and provide explainable AI insights.

## Features

- **Cryptographic Algorithm Detection**: Identifies classical and modern crypto algorithms (AES, RSA, SHA, etc.)
- **Structural Analysis**: Matches Data Flow Graphs to known patterns (Feistel, Merkle-Damgård, etc.)
- **Semantic Analysis**: Provides plain-language explanations of function purposes
- **Vulnerability Assessment**: Detects weak algorithms, implementation flaws, and security issues
- **Explainable AI**: Transparent reasoning for all detections and classifications
- **Confidence Scoring**: Each detection includes a confidence score (0.0 - 1.0)

## Supported Algorithms

### Symmetric Encryption
- Classical: Caesar, Vigenère, XOR, Substitution
- Modern: AES, DES, 3DES, Blowfish, ChaCha20, RC4

### Asymmetric Encryption
- RSA, ECDSA, ECDH, Ed25519, Curve25519, DSA

### Hash Functions
- SHA-1, SHA-2 (SHA-256, SHA-512), SHA-3, MD5, BLAKE2

### Encoding
- Base64, Base32, Hexadecimal

### Libraries Detected
- OpenSSL, libsodium, Crypto++, Microsoft CryptoAPI

## Installation

1. **Clone the repository**
```powershell
cd "d:\CypherRay Model"
```

2. **Install dependencies**
```powershell
pip install -r requirements.txt
```

3. **Configure environment**
Ensure your `.env` file contains:
```
OPENAI_API_KEY=your_openai_api_key_here
```

## Usage

### Start the Server

```powershell
python main.py
```

Or using uvicorn directly:
```powershell
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at `http://localhost:8000`

### API Documentation

Interactive API documentation is available at:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

### Analyze a Binary

**Using cURL:**
```powershell
curl -X POST "http://localhost:8000/analyze" `
  -F "file=@path\to\your\binary.exe" `
  -H "accept: application/json"
```

**Using Python:**
```python
import requests

with open("binary.exe", "rb") as f:
    files = {"file": f}
    response = requests.post("http://localhost:8000/analyze", files=files)
    
print(response.json())
```

### Response Structure

```json
{
  "file_metadata": {
    "file_type": "Mach-O 64-bit arm64 executable",
    "size_bytes": 33944,
    "md5": "2327060df93d89d38595e447e0bc206f",
    "sha1": "770ec7e5569b5001e880ce3315c50eda8a209dc8",
    "sha256": "b45fa9e3d6790a23dd60ba09a49c7756037f24da8cca2480176ada5ad43bbd84"
  },
  "detected_algorithms": [
    {
      "algorithm_name": "Caesar Cipher",
      "confidence_score": 0.85,
      "algorithm_class": "Symmetric Encryption",
      "structural_signature": "Substitution Cipher Pattern"
    },
    {
      "algorithm_name": "XOR Cipher",
      "confidence_score": 0.78,
      "algorithm_class": "Symmetric Encryption",
      "structural_signature": "Stream Cipher Pattern"
    }
  ],
  "function_analyses": [
    {
      "function_name": "encrypt_caesar",
      "function_summary": "Performs character rotation encryption using fixed shift offset",
      "semantic_tags": ["encryption", "classical", "substitution"],
      "is_crypto": true,
      "confidence_score": 0.85,
      "data_flow_pattern": "Character shift with modulo arithmetic"
    }
  ],
  "vulnerability_assessment": {
    "has_vulnerabilities": true,
    "severity": "High",
    "vulnerabilities": [
      "Uses weak classical ciphers (Caesar, XOR) inappropriate for security",
      "No evidence of authenticated encryption"
    ],
    "recommendations": [
      "Replace classical ciphers with modern algorithms like AES-GCM",
      "Implement proper key management",
      "Use authenticated encryption modes"
    ]
  },
  "overall_assessment": "Small demonstration binary implementing classical ciphers. Not suitable for production security use.",
  "xai_explanation": "Detailed explanation of detection methodology and confidence rationale..."
}
```

## API Endpoints

### `GET /`
Root endpoint with API information

### `GET /health`
Health check endpoint
- Returns service status
- Confirms OpenAI API key configuration

### `POST /analyze`
Analyze binary executable
- **Input**: Binary file (multipart/form-data)
- **Output**: Comprehensive analysis JSON

## System Prompt

The LLM system prompt is located in `prompts/system.md` and defines:
- Analysis framework and methodology
- Algorithm detection categories
- Structural pattern matching rules
- Semantic analysis guidelines
- XAI explainability requirements
- JSON output schema

## Security Considerations

- Binary files are analyzed using AI; results should be verified
- Never upload sensitive/proprietary binaries to public APIs
- Use private OpenAI instances for sensitive work
- Confidence scores indicate detection certainty, not absolute truth

## Architecture

```
CypherRay/
├── main.py                 # FastAPI application
├── prompts/
│   └── system.md          # LLM system prompt
├── .env                   # Environment variables (API keys)
├── requirements.txt       # Python dependencies
└── README.md             # Documentation
```

## Technical Details

### Structural Analysis
- **Data Flow Graph (DFG) Matching**: Traces execution patterns
- **Known Signatures**: Feistel networks, SPN, Merkle-Damgård, Sponge construction
- **Pattern Confidence Scoring**: 0.9-1.0 for exact matches

### Semantic Analysis
- **Function Summarization**: Plain-language explanations
- **Semantic Tagging**: Categorizes operations
- **Intent Detection**: Determines if functions are cryptographic


## Enhancements need to be done

- [ ] Support for disassembly integration (Ghidra, IDA Pro, radare2)
- [ ] Multi-model ensemble analysis
- [ ] Historical algorithm evolution tracking
- [ ] Automated vulnerability scoring (CVSS)
- [ ] Integration with threat intelligence feeds



Contributions welcome! Please submit pull requests or open issues for bugs/features.

## Support

For issues or questions, please open a GitHub issue or contact the development team.
