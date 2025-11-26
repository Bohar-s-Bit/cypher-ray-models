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
        
        # Comprehensive crypto constants database
        crypto_constants = {
            # AES Constants
            "AES_SBOX_FIRST_BYTES": bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b]),
            "AES_INV_SBOX_FIRST": bytes([0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36]),
            "AES_RCON_FIRST": bytes([0x01, 0x02, 0x04, 0x08, 0x10, 0x20]),
            
            # ChaCha20/Salsa20 Constants
            "CHACHA20_CONSTANT": b"expand 32-byte k",  # 0x61707865...
            "SALSA20_CONSTANT": b"expand 32-byte k",
            "CHACHA20_SIGMA": bytes([0x65, 0x78, 0x70, 0x61, 0x6e, 0x64]),  # "expand"
            
            # SHA Family
            "SHA256_K_FIRST": bytes.fromhex('428a2f98'),
            "SHA256_K_SECOND": bytes.fromhex('71374491'),
            "SHA256_INIT_H0": bytes.fromhex('6a09e667'),
            "SHA1_INIT_H0": bytes.fromhex('67452301'),
            "SHA1_INIT_H1": bytes.fromhex('efcdab89'),
            "SHA512_K_FIRST": bytes.fromhex('428a2f98d728ae22'),
            "SHA512_INIT_H0": bytes.fromhex('6a09e667f3bcc908'),
            
            # MD5
            "MD5_INIT_A": bytes.fromhex('67452301'),
            "MD5_INIT_B": bytes.fromhex('efcdab89'),
            "MD5_INIT_C": bytes.fromhex('98badcfe'),
            
            # DES/3DES
            "DES_IP_TABLE_START": bytes([58, 50, 42, 34, 26, 18]),
            "DES_SBOX1_FIRST": bytes([14, 4, 13, 1, 2, 15]),
            "DES_PC1_TABLE": bytes([57, 49, 41, 33, 25, 17]),
            
            # RSA/ECC Common Primes & Curves
            "SECP256K1_P_SUFFIX": bytes.fromhex('fffffffefffffc2f'),  # Last 8 bytes
            "SECP256K1_N_SUFFIX": bytes.fromhex('d0364141'),
            "P256_PRIME_SUFFIX": bytes.fromhex('ffffffff00000001'),
            
            # BLAKE2
            "BLAKE2B_IV0": bytes.fromhex('6a09e667f3bcc908'),
            "BLAKE2S_IV0": bytes.fromhex('6a09e667'),
            
            # RC4 (identity permutation check)
            "RC4_INIT_PATTERN": bytes(range(16)),  # First 16 bytes of S-box init
            
            # Common Base64 tables
            "BASE64_TABLE": b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef",
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
                            "offset": hex(section.vaddr + offset),
                            "algorithm_hint": _infer_algorithm_from_constant(const_name)
                        })
                except:
                    continue
        
        # Group by algorithm for better presentation
        algorithm_groups = {}
        for const in detected_constants:
            algo = const["algorithm_hint"]
            if algo not in algorithm_groups:
                algorithm_groups[algo] = []
            algorithm_groups[algo].append(const["constant_name"])
        
        return {
            "detected_constants": detected_constants,
            "total_found": len(detected_constants),
            "algorithm_groups": algorithm_groups,
            "confidence_level": _calculate_confidence(algorithm_groups)
        }
    except Exception as e:
        return {"error": f"Failed to detect crypto constants: {str(e)}"}


def _infer_algorithm_from_constant(const_name: str) -> str:
    """Infer algorithm family from constant name"""
    if "AES" in const_name:
        return "AES"
    elif "CHACHA" in const_name or "SALSA" in const_name:
        return "ChaCha20/Salsa20"
    elif "SHA256" in const_name:
        return "SHA-256"
    elif "SHA512" in const_name:
        return "SHA-512"
    elif "SHA1" in const_name:
        return "SHA-1"
    elif "MD5" in const_name:
        return "MD5"
    elif "DES" in const_name:
        return "DES/3DES"
    elif "SECP" in const_name or "P256" in const_name:
        return "ECC"
    elif "BLAKE" in const_name:
        return "BLAKE2"
    elif "RC4" in const_name:
        return "RC4"
    elif "BASE64" in const_name:
        return "Base64"
    return "Unknown"


def _calculate_confidence(algorithm_groups: Dict[str, list]) -> str:
    """Calculate overall confidence based on number of constants found"""
    max_constants = max(len(v) for v in algorithm_groups.values()) if algorithm_groups else 0
    
    if max_constants >= 4:
        return "very_high"
    elif max_constants >= 2:
        return "high"
    elif max_constants >= 1:
        return "medium"
    return "low"
