"""
Angr tool for extracting function information from binaries.
"""

from typing import Dict, Any

try:
    import angr
    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False


def angr_extract_functions(binary_path: str, limit: int = 50) -> Dict[str, Any]:
    """
    Extract function information from binary using Angr's CFG analysis.
    Returns function addresses, names, and basic block counts.
    
    Args:
        binary_path: Path to the binary file
        limit: Maximum number of functions to return
        
    Returns:
        Dict containing function information or error message
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
