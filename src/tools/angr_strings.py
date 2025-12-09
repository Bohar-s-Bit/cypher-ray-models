"""
Angr tool for extracting and analyzing strings in binaries.
"""

from typing import Dict, Any
from .angr_loader_helper import load_binary_with_fallback

try:
    import angr
    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False


def angr_analyze_strings(binary_path: str) -> Dict[str, Any]:
    """
    Extract readable strings from binary that may indicate cryptographic operations.
    
    Args:
        binary_path: Path to the binary file
        
    Returns:
        Dict containing crypto-related strings or error message
    """
    try:
        if not ANGR_AVAILABLE:
            return {"error": "Angr is not available in this environment"}
        
        # Use blob loader fallback for raw binaries
        project = load_binary_with_fallback(binary_path, auto_load_libs=False)
        
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
