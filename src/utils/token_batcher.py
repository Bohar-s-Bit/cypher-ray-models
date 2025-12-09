"""
Token-aware batching utility for handling large function lists.
Ensures we don't exceed Claude's context window when analyzing many functions.
"""

import os
import json
from typing import List, Dict, Any, Iterator
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Try to import tiktoken for accurate token counting
try:
    import tiktoken
    TIKTOKEN_AVAILABLE = True
except ImportError:
    TIKTOKEN_AVAILABLE = False
    logger.warning("tiktoken not available - using character-based estimation")


class TokenBatcher:
    """Batches data based on token limits to prevent context overflow."""
    
    def __init__(
        self,
        max_tokens_per_batch: int = None,
        model_name: str = "claude-3-5-haiku-20241022"
    ):
        """
        Initialize token batcher.
        
        Args:
            max_tokens_per_batch: Maximum tokens per batch (default from env or 50000)
            model_name: Model name for accurate token counting
        """
        # Get from environment or use default
        self.max_tokens = max_tokens_per_batch or int(
            os.getenv('MAX_TOKENS_PER_BATCH', '50000')
        )
        
        # For Claude, we estimate tokens since tiktoken is for OpenAI
        # Claude tokens ≈ characters / 4 (rough estimate)
        # We'll be conservative and use characters / 3.5
        self.chars_per_token = 3.5
        
        logger.info(f"TokenBatcher initialized: max {self.max_tokens} tokens per batch")
    
    def estimate_tokens(self, text: str) -> int:
        """
        Estimate token count for given text.
        
        Args:
            text: Input text
            
        Returns:
            Estimated token count
        """
        if TIKTOKEN_AVAILABLE:
            # Use tiktoken for better estimation (even though it's for GPT)
            try:
                enc = tiktoken.get_encoding("cl100k_base")
                return len(enc.encode(text))
            except Exception:
                pass
        
        # Fallback: character-based estimation
        return int(len(text) / self.chars_per_token)
    
    def estimate_tokens_from_dict(self, data: Dict[str, Any]) -> int:
        """
        Estimate tokens from dictionary (will be JSON serialized).
        
        Args:
            data: Dictionary to estimate
            
        Returns:
            Estimated token count
        """
        # Serialize to JSON to get accurate character count
        json_str = json.dumps(data)
        return self.estimate_tokens(json_str)
    
    def batch_functions(
        self,
        functions: List[Dict[str, Any]],
        include_metadata: bool = True
    ) -> Iterator[Dict[str, Any]]:
        """
        Batch functions into groups that fit within token limits.
        
        Args:
            functions: List of function dictionaries
            include_metadata: Whether to include metadata in each batch
            
        Yields:
            Batches of functions with metadata
        """
        if not functions:
            yield {"functions": [], "batch_info": {"total_batches": 0, "batch_number": 0}}
            return
        
        # Calculate overhead for wrapper structure
        overhead = self.estimate_tokens_from_dict({
            "functions": [],
            "batch_info": {"total_batches": 1, "batch_number": 1}
        })
        
        # Reserve tokens for overhead
        available_tokens = self.max_tokens - overhead - 1000  # Safety margin
        
        batches = []
        current_batch = []
        current_tokens = 0
        
        for func in functions:
            func_tokens = self.estimate_tokens_from_dict(func)
            
            # If single function exceeds limit, include it anyway but warn
            if func_tokens > available_tokens:
                logger.warning(
                    f"Function {func.get('name', 'unknown')} ({func_tokens} tokens) "
                    f"exceeds batch limit ({available_tokens} tokens) - including anyway"
                )
                # Flush current batch if not empty
                if current_batch:
                    batches.append(current_batch)
                    current_batch = []
                    current_tokens = 0
                # Add oversized function as its own batch
                batches.append([func])
                continue
            
            # Check if adding this function would exceed limit
            if current_tokens + func_tokens > available_tokens:
                # Flush current batch
                batches.append(current_batch)
                current_batch = [func]
                current_tokens = func_tokens
            else:
                # Add to current batch
                current_batch.append(func)
                current_tokens += func_tokens
        
        # Don't forget the last batch
        if current_batch:
            batches.append(current_batch)
        
        total_batches = len(batches)
        logger.info(
            f"Batched {len(functions)} functions into {total_batches} batches "
            f"(avg {len(functions) / max(total_batches, 1):.1f} functions/batch)"
        )
        
        # Yield batches with metadata
        for idx, batch in enumerate(batches, start=1):
            yield {
                "functions": batch,
                "batch_info": {
                    "batch_number": idx,
                    "total_batches": total_batches,
                    "functions_in_batch": len(batch),
                    "estimated_tokens": sum(
                        self.estimate_tokens_from_dict(f) for f in batch
                    )
                }
            }
    
    def batch_data_by_size(
        self,
        items: List[Any],
        max_batch_size: int = None
    ) -> Iterator[List[Any]]:
        """
        Simple batching by count (not token-aware).
        
        Args:
            items: List of items to batch
            max_batch_size: Max items per batch (default 10)
            
        Yields:
            Batches of items
        """
        batch_size = max_batch_size or 10
        
        for i in range(0, len(items), batch_size):
            yield items[i:i + batch_size]
    
    def should_batch(self, data_size: int) -> bool:
        """
        Determine if data should be batched based on size.
        
        Args:
            data_size: Estimated token count of data
            
        Returns:
            True if batching is recommended
        """
        # Batch if data exceeds 80% of max tokens
        threshold = int(self.max_tokens * 0.8)
        return data_size > threshold


# Global instance for easy access
_default_batcher = None


def get_token_batcher() -> TokenBatcher:
    """Get or create the default token batcher instance."""
    global _default_batcher
    if _default_batcher is None:
        _default_batcher = TokenBatcher()
    return _default_batcher


def batch_functions_for_analysis(
    functions: List[Dict[str, Any]]
) -> Iterator[Dict[str, Any]]:
    """
    Convenience function to batch functions using default batcher.
    
    Args:
        functions: List of function dictionaries
        
    Yields:
        Batches of functions
    """
    batcher = get_token_batcher()
    yield from batcher.batch_functions(functions)
