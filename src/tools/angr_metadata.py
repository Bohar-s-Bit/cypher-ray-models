"""
Angr tool for extracting binary metadata.
"""

import hashlib
import os
from typing import Dict, Any

try:
    import angr
    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False


def angr_analyze_binary_metadata(binary_path: str) -> Dict[str, Any]:
    """
    Extract basic metadata from binary using Angr.
    Returns file type, architecture, entry point, and cryptographic hashes.
    
    Args:
        binary_path: Path to the binary file
        
    Returns:
        Dict containing metadata or error message
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
        
        # Try to load binary with Angr (with blob fallback for raw binaries)
        project = None
        try:
            project = angr.Project(binary_path, auto_load_libs=False)
        except Exception as load_error:
            # If standard loaders fail, try blob loader for raw binaries (firmware, shellcode, etc.)
            if "loader backend" in str(load_error).lower() or "blob" in str(load_error).lower():
                try:
                    project = angr.Project(binary_path, 
                                         main_opts={'backend': 'blob', 'arch': 'x86_64'},
                                         auto_load_libs=False)
                except:
                    # Blob loader also failed, return hashes only
                    return {
                        "file_type": "raw binary (unknown format)",
                        "architecture": "unknown",
                        "size_bytes": os.path.getsize(binary_path),
                        "entry_point": "0x0",
                        "md5": md5_hash,
                        "sha1": sha1_hash,
                        "sha256": sha256_hash,
                        "endianness": "unknown",
                        "bits": 0
                    }
            else:
                raise load_error
        
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
