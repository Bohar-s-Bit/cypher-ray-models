"""
Core Angr tools manager - centralizes all Angr analysis functions.
"""

from typing import Dict, Any, Callable
from src.tools.angr_metadata import angr_analyze_binary_metadata
from src.tools.angr_functions import angr_extract_functions
from src.tools.angr_strings import angr_analyze_strings
from src.tools.angr_dataflow import angr_analyze_function_dataflow
from src.tools.angr_constants import angr_detect_crypto_constants


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
ANGR_FUNCTION_MAP: Dict[str, Callable] = {
    "angr_analyze_binary_metadata": angr_analyze_binary_metadata,
    "angr_extract_functions": angr_extract_functions,
    "angr_analyze_strings": angr_analyze_strings,
    "angr_analyze_function_dataflow": angr_analyze_function_dataflow,
    "angr_detect_crypto_constants": angr_detect_crypto_constants
}


def get_angr_tool(tool_name: str) -> Callable:
    """Get an Angr tool function by name."""
    return ANGR_FUNCTION_MAP.get(tool_name)


def check_angr_available() -> bool:
    """Check if Angr is available."""
    try:
        import angr
        return True
    except ImportError:
        return False
