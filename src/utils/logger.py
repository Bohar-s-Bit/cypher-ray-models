"""
Centralized logging system for CypherRay ML Service.
Provides structured logging with file and console outputs.
"""

import logging
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional
import json


class CypherRayLogger:
    """Centralized logger for the CypherRay system."""
    
    _loggers = {}
    
    @staticmethod
    def get_logger(name: str, log_level: str = "INFO") -> logging.Logger:
        """
        Get or create a logger instance.
        
        Args:
            name: Name of the logger (usually module name)
            log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            
        Returns:
            Configured logger instance
        """
        if name in CypherRayLogger._loggers:
            return CypherRayLogger._loggers[name]
        
        # Create logger
        logger = logging.getLogger(name)
        logger.setLevel(getattr(logging, log_level.upper()))
        
        # Prevent duplicate handlers
        if logger.handlers:
            return logger
        
        # Create formatters
        detailed_formatter = logging.Formatter(
            fmt='%(asctime)s | %(levelname)-8s | %(name)s | %(funcName)s:%(lineno)d | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        console_formatter = logging.Formatter(
            fmt='%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
            datefmt='%H:%M:%S'
        )
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
        
        # File handler
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        # Main log file (all logs)
        file_handler = logging.FileHandler(
            log_dir / f"cypherray_{datetime.now().strftime('%Y%m%d')}.log"
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(detailed_formatter)
        logger.addHandler(file_handler)
        
        # Error log file (errors only)
        error_handler = logging.FileHandler(
            log_dir / f"cypherray_errors_{datetime.now().strftime('%Y%m%d')}.log"
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(detailed_formatter)
        logger.addHandler(error_handler)
        
        # Cache logger
        CypherRayLogger._loggers[name] = logger
        
        return logger
    
    @staticmethod
    def log_analysis_start(logger: logging.Logger, binary_path: str, options: dict):
        """Log the start of a binary analysis."""
        logger.info(f"Starting analysis for: {binary_path}")
        logger.debug(f"Analysis options: {json.dumps(options, indent=2)}")
    
    @staticmethod
    def log_analysis_complete(logger: logging.Logger, binary_path: str, duration: float, cost: float):
        """Log successful analysis completion."""
        logger.info(
            f"Analysis complete for: {binary_path} | "
            f"Duration: {duration:.2f}s | Cost: ${cost:.4f}"
        )
    
    @staticmethod
    def log_model_call(logger: logging.Logger, model: str, tokens_in: int, tokens_out: int, cost: float):
        """Log an LLM API call."""
        logger.debug(
            f"Model: {model} | Tokens: {tokens_in} in, {tokens_out} out | Cost: ${cost:.6f}"
        )
    
    @staticmethod
    def log_error(logger: logging.Logger, error: Exception, context: Optional[dict] = None):
        """Log an error with context."""
        logger.error(f"Error: {str(error)}", exc_info=True)
        if context:
            logger.error(f"Context: {json.dumps(context, indent=2)}")
    
    @staticmethod
    def log_cache_hit(logger: logging.Logger, cache_key: str):
        """Log a cache hit."""
        logger.info(f"Cache HIT: {cache_key[:16]}...")
    
    @staticmethod
    def log_cache_miss(logger: logging.Logger, cache_key: str):
        """Log a cache miss."""
        logger.debug(f"Cache MISS: {cache_key[:16]}...")


# Convenience function
def get_logger(name: str, log_level: str = "INFO") -> logging.Logger:
    """Get a logger instance - convenience wrapper."""
    return CypherRayLogger.get_logger(name, log_level)


# Example usage
if __name__ == "__main__":
    # Test the logger
    logger = get_logger("test_module")
    
    logger.debug("This is a debug message")
    logger.info("This is an info message")
    logger.warning("This is a warning message")
    logger.error("This is an error message")
    
    CypherRayLogger.log_analysis_start(
        logger, 
        "/path/to/binary", 
        {"depth": "full", "architecture": "ARM"}
    )
    
    CypherRayLogger.log_model_call(logger, "gpt-4o", 1000, 500, 0.0075)
    CypherRayLogger.log_analysis_complete(logger, "/path/to/binary", 45.2, 0.15)
    
    print("\n✅ Logger test complete. Check logs/ directory for output files.")
