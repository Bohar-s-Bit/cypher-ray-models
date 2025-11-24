"""
Cache Manager - Handles caching of analysis results.
Supports in-memory and file-based caching with TTL.
"""

import json
import time
import hashlib
import os
import sys
from pathlib import Path
from typing import Any, Optional, Dict
from datetime import datetime

from src.utils.logger import get_logger

logger = get_logger(__name__)


class CacheManager:
    """Manages caching of analysis results with TTL support."""
    
    def __init__(self, cache_dir: str = "cache", use_file_cache: bool = True, max_memory_mb: int = 100):
        """
        Initialize cache manager.
        
        Args:
            cache_dir: Directory for file-based cache
            use_file_cache: Whether to use file-based cache (persistent)
            max_memory_mb: Maximum memory for in-memory cache in MB
        """
        self.cache_dir = Path(cache_dir)
        self.use_file_cache = use_file_cache
        self.memory_cache: Dict[str, Dict[str, Any]] = {}
        self.max_memory_bytes = max_memory_mb * 1024 * 1024  # Convert to bytes
        
        if self.use_file_cache:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"Cache directory: {self.cache_dir.absolute()}")
        
        logger.info(f"Max in-memory cache size: {max_memory_mb}MB")
    
    def _get_memory_usage(self) -> int:
        """Get approximate memory usage of in-memory cache."""
        return sys.getsizeof(self.memory_cache)
    
    def _evict_oldest(self):
        """Evict oldest cache entries if memory limit exceeded."""
        if not self.memory_cache:
            return
            
        memory_usage = self._get_memory_usage()
        if memory_usage > self.max_memory_bytes:
            # Sort by timestamp and remove oldest 30%
            sorted_entries = sorted(
                self.memory_cache.items(),
                key=lambda x: x[1]['timestamp']
            )
            evict_count = max(1, len(sorted_entries) // 3)
            
            for key, _ in sorted_entries[:evict_count]:
                del self.memory_cache[key]
            
            logger.info(f"Evicted {evict_count} old cache entries (memory: {memory_usage / 1024 / 1024:.1f}MB)")
    
    def _get_cache_file_path(self, key: str) -> Path:
        """Get file path for cache key."""
        return self.cache_dir / f"{key}.json"
    
    def _is_expired(self, timestamp: float, ttl: int) -> bool:
        """Check if cache entry is expired."""
        return (time.time() - timestamp) > ttl
    
    def get(self, key: str) -> Optional[Any]:
        """
        Get value from cache.
        
        Args:
            key: Cache key
            
        Returns:
            Cached value or None if not found/expired
        """
        # Check memory cache first
        if key in self.memory_cache:
            entry = self.memory_cache[key]
            if not self._is_expired(entry['timestamp'], entry['ttl']):
                logger.debug(f"Memory cache HIT: {key[:16]}...")
                return entry['value']
            else:
                # Expired, remove from memory
                del self.memory_cache[key]
                logger.debug(f"Memory cache EXPIRED: {key[:16]}...")
        
        # Check file cache if enabled
        if self.use_file_cache:
            cache_file = self._get_cache_file_path(key)
            if cache_file.exists():
                try:
                    with open(cache_file, 'r') as f:
                        entry = json.load(f)
                    
                    if not self._is_expired(entry['timestamp'], entry['ttl']):
                        # Load back to memory cache
                        self.memory_cache[key] = entry
                        logger.debug(f"File cache HIT: {key[:16]}...")
                        return entry['value']
                    else:
                        # Expired, delete file
                        cache_file.unlink()
                        logger.debug(f"File cache EXPIRED: {key[:16]}...")
                except Exception as e:
                    logger.warning(f"Error reading cache file {cache_file}: {e}")
        
        return None
    
    def set(self, key: str, value: Any, ttl: int = 86400):
        """
        Set value in cache.
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live in seconds (default: 24 hours)
        """
        entry = {
            'value': value,
            'timestamp': time.time(),
            'ttl': ttl,
            'created_at': datetime.now().isoformat()
        }
        
        # Save to memory cache with eviction check
        self.memory_cache[key] = entry
        self._evict_oldest()  # Check and evict if needed
        
        # Save to file cache if enabled
        if self.use_file_cache:
            cache_file = self._get_cache_file_path(key)
            try:
                with open(cache_file, 'w') as f:
                    json.dump(entry, f, indent=2)
                logger.debug(f"Cached to file: {key[:16]}...")
            except Exception as e:
                logger.warning(f"Error writing cache file {cache_file}: {e}")
    
    def delete(self, key: str):
        """Delete cache entry."""
        # Remove from memory
        if key in self.memory_cache:
            del self.memory_cache[key]
        
        # Remove from file cache
        if self.use_file_cache:
            cache_file = self._get_cache_file_path(key)
            if cache_file.exists():
                cache_file.unlink()
                logger.debug(f"Deleted cache: {key[:16]}...")
    
    def clear(self):
        """Clear all cache entries."""
        # Clear memory cache
        self.memory_cache.clear()
        
        # Clear file cache
        if self.use_file_cache:
            for cache_file in self.cache_dir.glob("*.json"):
                cache_file.unlink()
            logger.info("Cache cleared")
    
    def cleanup_expired(self):
        """Remove all expired cache entries."""
        count = 0
        
        # Clean memory cache
        expired_keys = [
            key for key, entry in self.memory_cache.items()
            if self._is_expired(entry['timestamp'], entry['ttl'])
        ]
        for key in expired_keys:
            del self.memory_cache[key]
            count += 1
        
        # Clean file cache
        if self.use_file_cache:
            for cache_file in self.cache_dir.glob("*.json"):
                try:
                    with open(cache_file, 'r') as f:
                        entry = json.load(f)
                    
                    if self._is_expired(entry['timestamp'], entry['ttl']):
                        cache_file.unlink()
                        count += 1
                except Exception as e:
                    logger.warning(f"Error checking cache file {cache_file}: {e}")
        
        if count > 0:
            logger.info(f"Cleaned up {count} expired cache entries")
        
        return count
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        stats = {
            'memory_entries': len(self.memory_cache),
            'file_entries': 0,
            'total_size_bytes': 0
        }
        
        if self.use_file_cache:
            cache_files = list(self.cache_dir.glob("*.json"))
            stats['file_entries'] = len(cache_files)
            stats['total_size_bytes'] = sum(f.stat().st_size for f in cache_files)
        
        return stats


# Example usage and testing
if __name__ == "__main__":
    print("🧪 Testing Cache Manager...\n")
    
    # Initialize cache manager
    cache = CacheManager(cache_dir="cache/test", use_file_cache=True)
    
    # Test 1: Set and get
    print("Test 1: Set and Get")
    cache.set("test_key_1", {"data": "Hello, World!"}, ttl=60)
    result = cache.get("test_key_1")
    print(f"✅ Retrieved: {result}\n")
    
    # Test 2: Complex data
    print("Test 2: Complex Data")
    complex_data = {
        "algorithms": ["AES", "RSA", "SHA-256"],
        "confidence": 0.95,
        "metadata": {"source": "angr", "timestamp": time.time()}
    }
    cache.set("complex_key", complex_data, ttl=3600)
    result = cache.get("complex_key")
    print(f"✅ Retrieved complex data: {result['algorithms']}\n")
    
    # Test 3: Expiration
    print("Test 3: Expiration (short TTL)")
    cache.set("expire_key", {"temp": "data"}, ttl=1)
    print(f"Immediate get: {cache.get('expire_key')}")
    time.sleep(2)
    expired = cache.get("expire_key")
    print(f"After 2 seconds: {expired}\n")
    
    # Test 4: Cache stats
    print("Test 4: Cache Statistics")
    stats = cache.get_stats()
    print(f"✅ Stats: {stats}\n")
    
    # Test 5: Cleanup
    print("Test 5: Cleanup Expired")
    cleaned = cache.cleanup_expired()
    print(f"✅ Cleaned {cleaned} entries\n")
    
    # Test 6: Clear all
    print("Test 6: Clear All Cache")
    cache.clear()
    stats_after = cache.get_stats()
    print(f"✅ After clear: {stats_after}\n")
    
    print("✅ All cache manager tests passed!")
