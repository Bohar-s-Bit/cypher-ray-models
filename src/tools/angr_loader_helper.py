"""
Helper utilities for loading binaries with Angr, including blob loader fallback.
"""

try:
    import angr
    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False


def load_binary_with_fallback(binary_path: str, auto_load_libs: bool = False):
    """
    Load a binary with Angr, automatically falling back to blob loader for raw binaries.
    
    This handles cases where the binary doesn't have standard executable headers
    (ELF/PE/Mach-O), such as:
    - Firmware dumps
    - Shellcode
    - Extracted crypto libraries
    - Obfuscated/packed binaries
    
    Args:
        binary_path: Path to the binary file
        auto_load_libs: Whether to load shared libraries (default: False)
        
    Returns:
        angr.Project instance
        
    Raises:
        Exception: If both standard and blob loaders fail
    """
    if not ANGR_AVAILABLE:
        raise ImportError("Angr is not available")
    
    # Try standard loaders first (ELF, PE, Mach-O, etc.)
    try:
        return angr.Project(binary_path, auto_load_libs=auto_load_libs)
    except Exception as load_error:
        error_msg = str(load_error).lower()
        
        # Check if it's a loader backend issue (suggests raw binary)
        if "loader backend" in error_msg or "blob" in error_msg:
            # Try blob loader for raw binaries
            # Try multiple architectures since we don't know the format
            architectures = ['x86_64', 'i386', 'arm', 'aarch64', 'mips']
            
            for arch in architectures:
                try:
                    project = angr.Project(
                        binary_path,
                        main_opts={
                            'backend': 'blob',
                            'arch': arch,
                            'base_addr': 0x0,  # Start at address 0
                        },
                        auto_load_libs=False
                    )
                    # If successful, return it
                    return project
                except:
                    continue  # Try next architecture
            
            # If all architectures failed, raise original error
            raise Exception(f"Failed to load binary with any architecture. Original error: {load_error}")
        else:
            # Not a loader issue, re-raise original error
            raise load_error


def is_blob_loaded(project) -> bool:
    """
    Check if a project was loaded using the blob loader (raw binary).
    
    Returns:
        True if loaded as blob, False if loaded with standard loader
    """
    if not project or not hasattr(project, 'loader'):
        return False
    
    try:
        return project.loader.main_object.os == 'unknown'
    except:
        return False
