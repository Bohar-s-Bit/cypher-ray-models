"""
YARA-based cryptographic signature detector.
Scans binaries for known crypto patterns using compiled YARA rules.
"""

import os
from typing import Dict, Any, List, Optional
from pathlib import Path

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

from src.utils.logger import get_logger

logger = get_logger(__name__)


class YaraDetector:
    """YARA-based cryptographic pattern detector."""
    
    def __init__(self, rules_path: Optional[str] = None):
        """
        Initialize YARA detector with compiled rules.
        
        Args:
            rules_path: Path to YARA rules file (default: config/crypto_signatures.yar)
        """
        if not YARA_AVAILABLE:
            logger.warning("YARA is not available - yara-python not installed")
            self.rules = None
            return
        
        if rules_path is None:
            # Default to crypto_signatures.yar in config directory
            rules_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                "config",
                "crypto_signatures.yar"
            )
        
        try:
            if not os.path.exists(rules_path):
                logger.error(f"YARA rules file not found: {rules_path}")
                self.rules = None
                return
            
            self.rules = yara.compile(filepath=rules_path)
            logger.info(f"✅ YARA rules compiled successfully from {rules_path}")
        except Exception as e:
            logger.error(f"Failed to compile YARA rules: {e}")
            self.rules = None
    
    def scan_binary(self, binary_path: str) -> Dict[str, Any]:
        """
        Scan a binary file for cryptographic signatures.
        
        Args:
            binary_path: Path to the binary file to scan
            
        Returns:
            Dict containing YARA scan results
        """
        if not YARA_AVAILABLE:
            return {
                "yara_available": False,
                "error": "YARA is not installed (pip install yara-python)"
            }
        
        if self.rules is None:
            return {
                "yara_available": False,
                "error": "YARA rules not compiled"
            }
        
        try:
            # Scan the binary file with 45s timeout
            matches = self.rules.match(binary_path, timeout=45)
            
            # Process matches
            detections = []
            algorithm_hints = set()
            severity_counts = {"high": 0, "medium": 0, "low": 0}
            
            for match in matches:
                # Extract metadata
                meta = {k: v for k, v in match.meta.items()}
                algorithm = meta.get("algorithm", "Unknown")
                severity = meta.get("severity", "low")
                
                # Collect matched strings and their offsets
                matched_strings = []
                for string_match in match.strings:
                    matched_strings.append({
                        "identifier": string_match.identifier,
                        "offset": hex(string_match.instances[0].offset),
                        "length": len(string_match.instances[0].matched_data)
                    })
                
                detection = {
                    "rule_name": match.rule,
                    "algorithm": algorithm,
                    "description": meta.get("description", ""),
                    "severity": severity,
                    "matched_strings": matched_strings,
                    "match_count": len(matched_strings)
                }
                
                detections.append(detection)
                algorithm_hints.add(algorithm)
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Build summary
            summary = {
                "total_rules_matched": len(matches),
                "unique_algorithms_detected": len(algorithm_hints),
                "algorithms": sorted(list(algorithm_hints)),
                "severity_breakdown": severity_counts,
                "crypto_confidence": self._calculate_confidence(detections)
            }
            
            logger.info(f"YARA scan complete: {len(matches)} rules matched, {len(algorithm_hints)} algorithms detected")
            
            return {
                "yara_available": True,
                "scan_successful": True,
                "summary": summary,
                "detections": detections
            }
            
        except Exception as e:
            logger.error(f"YARA scan failed: {e}", exc_info=True)
            return {
                "yara_available": True,
                "scan_successful": False,
                "error": str(e)
            }
    
    def _calculate_confidence(self, detections: List[Dict]) -> float:
        """
        Calculate overall crypto confidence based on YARA matches.
        
        Args:
            detections: List of YARA rule matches
            
        Returns:
            Confidence score (0.0 - 1.0)
        """
        if not detections:
            return 0.0
        
        # Weight by severity
        severity_weights = {"high": 1.0, "medium": 0.6, "low": 0.3}
        
        total_weight = 0.0
        for detection in detections:
            severity = detection.get("severity", "low")
            weight = severity_weights.get(severity, 0.3)
            # More matches of the same rule increases confidence
            match_multiplier = min(detection.get("match_count", 1) / 10.0, 1.0)
            total_weight += weight * (1 + match_multiplier)
        
        # Normalize to 0-1 scale
        # Multiple high-severity matches quickly push confidence high
        confidence = min(total_weight / (len(detections) + 5), 1.0)
        
        # Boost confidence if multiple different algorithms detected
        unique_algos = len(set(d.get("algorithm", "") for d in detections))
        if unique_algos > 2:
            confidence = min(confidence * 1.2, 1.0)
        
        return round(confidence, 2)
    
    def get_function_yara_tags(
        self,
        binary_path: str,
        function_address: int,
        function_size: int
    ) -> List[str]:
        """
        Get YARA tags for a specific function by checking if any YARA matches
        fall within the function's address range.
        
        Args:
            binary_path: Path to binary file
            function_address: Starting address of function
            function_size: Size of function in bytes
            
        Returns:
            List of YARA rule names that matched within this function
        """
        if self.rules is None:
            return []
        
        try:
            matches = self.rules.match(binary_path)
            tags = []
            
            func_start = function_address
            func_end = function_address + function_size
            
            for match in matches:
                for string_match in match.strings:
                    offset = string_match.instances[0].offset
                    if func_start <= offset < func_end:
                        tags.append(match.rule)
                        break  # One match per rule is enough
            
            return tags
            
        except Exception as e:
            logger.error(f"Failed to get YARA tags for function at {hex(function_address)}: {e}")
            return []


def yara_scan_binary(binary_path: str) -> Dict[str, Any]:
    """
    Standalone function for scanning a binary with YARA rules.
    
    Args:
        binary_path: Path to binary file
        
    Returns:
        YARA scan results
    """
    detector = YaraDetector()
    return detector.scan_binary(binary_path)


def yara_get_function_tags(
    binary_path: str,
    function_address: int,
    function_size: int
) -> List[str]:
    """
    Get YARA tags for a specific function.
    
    Args:
        binary_path: Path to binary file
        function_address: Function start address
        function_size: Function size in bytes
        
    Returns:
        List of matching YARA rule names
    """
    detector = YaraDetector()
    return detector.get_function_yara_tags(binary_path, function_address, function_size)
