"""
Angr tool for detecting known cryptographic constants in binaries.
"""

from typing import Dict, Any

try:
    import angr
    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False


def angr_detect_crypto_constants(binary_path: str) -> Dict[str, Any]:
    """
    Search for known cryptographic constants in the binary
    (e.g., AES S-box values, SHA round constants, etc.)
    
    Args:
        binary_path: Path to the binary file
        
    Returns:
        Dict containing detected constants or error message
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
