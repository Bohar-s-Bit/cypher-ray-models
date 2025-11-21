"""
Angr tool for analyzing data flow patterns in functions.
"""

from typing import Dict, Any

try:
    import angr
    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False


def angr_analyze_function_dataflow(binary_path: str, function_address: str, max_depth: int = 20) -> Dict[str, Any]:
    """
    Analyze data flow patterns in a specific function to detect crypto operations.
    Looks for characteristic patterns like XOR loops, rotations, S-box lookups.
    
    Args:
        binary_path: Path to the binary file
        function_address: Hexadecimal address of the function
        max_depth: Maximum number of basic blocks to analyze
        
    Returns:
        Dict containing detected patterns or error message
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
