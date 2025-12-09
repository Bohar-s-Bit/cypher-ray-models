# Backend Metadata Integration Fix - December 9, 2025

## Problem Identified

Frontend showing "unknown" for file metadata fields:
```
File Type: unknown
Size: N/A
Architecture: unknown
MD5: not_computed
SHA-256: not_computed
```

But logs show **successful analysis**:
- ✅ 8 algorithms detected
- ✅ 11 YARA matches
- ✅ Clean logs (no CFGFast spam)

**Root Cause**: ML service was not properly injecting Angr metadata into final synthesis response.

---

## Data Flow Analysis

### 1. ML Service Extracts Metadata (Stage 2)
**File**: `src/tools/angr_metadata.py`
```python
{
    "file_type": "Linux AMD64",
    "architecture": "AMD64",
    "size_bytes": 432380,
    "md5": "abc123...",
    "sha256": "def456...",
    "entry_point": "0x1000"
}
```

### 2. Claude Final Synthesis (Stage 7)
**Problem**: Claude sometimes returns:
```json
{
    "file_metadata": {
        "size": "not_computed",  // ❌ String instead of number!
        "format": "unknown"
    }
}
```

### 3. Backend Normalization
**File**: `services/analysis.service.js` (Line 95-115)
```javascript
const data = rawResults.analysis || rawResults;
const fileMetadata = data.file_metadata || {};

// Maps fields:
file_type: fileMetadata.format || fileMetadata.file_type
size_bytes: fileMetadata.size || fileMetadata.size_bytes
md5: fileMetadata.md5
sha256: fileMetadata.sha256
architecture: fileMetadata.architecture
```

---

## Fix Applied

**File**: `src/core/analysis_pipeline.py` (Lines 750-770)

### Added Metadata Injection After Claude Synthesis
```python
# **CRITICAL FIX**: Force correct file metadata from Angr
if 'metadata' in angr_results and angr_results['metadata']:
    angr_meta = angr_results['metadata']
    if 'file_metadata' not in final_report:
        final_report['file_metadata'] = {}
    
    # Override with actual Angr values
    file_type_value = angr_meta.get('file_type', 'unknown')
    final_report['file_metadata']['file_type'] = file_type_value
    final_report['file_metadata']['format'] = file_type_value
    final_report['file_metadata']['architecture'] = angr_meta.get('architecture', 'unknown')
    
    # CRITICAL: Ensure size is NUMBER, not string "not_computed"
    final_report['file_metadata']['size'] = angr_meta.get('size_bytes', 0)
    final_report['file_metadata']['size_bytes'] = angr_meta.get('size_bytes', 0)
    
    # Hashes (strings OK for these)
    final_report['file_metadata']['md5'] = angr_meta.get('md5', 'not_computed')
    final_report['file_metadata']['sha1'] = angr_meta.get('sha1', 'not_computed')
    final_report['file_metadata']['sha256'] = angr_meta.get('sha256', 'not_computed')
    final_report['file_metadata']['stripped'] = final_report['file_metadata'].get('stripped', False)
    
    logger.info(f"✅ Injected Angr metadata: {file_type_value} ({angr_meta.get('size_bytes')} bytes)")
```

### Key Changes
1. **Always inject Angr metadata** after Claude's response
2. **Override Claude's values** with real Angr data
3. **Dual field names** for backend compatibility:
   - `file_type` AND `format` (backend checks both)
   - `size` AND `size_bytes` (backend checks both)
4. **Type safety**: Ensures `size` is always a number (0 if unknown), never string "not_computed"

---

## Expected Response Format

**ML Service → Backend**:
```json
{
    "status": "success",
    "analysis": {
        "file_metadata": {
            "file_type": "Linux AMD64",
            "format": "Linux AMD64",
            "architecture": "AMD64",
            "size": 432380,
            "size_bytes": 432380,
            "md5": "abc123...",
            "sha1": "def456...",
            "sha256": "ghi789...",
            "stripped": false
        },
        "detected_algorithms": [...]
    }
}
```

**Backend Normalization → Frontend**:
```javascript
{
    file_metadata: {
        file_type: "Linux AMD64",     // ✅ Real value
        size_bytes: 432380,            // ✅ Number
        md5: "abc123...",              // ✅ Real hash
        sha256: "ghi789...",           // ✅ Real hash
        architecture: "AMD64",         // ✅ Real value
        stripped: false
    }
}
```

---

## Testing

**1. Restart ML Service**:
```bash
cd /Users/mac/Downloads/Projects/SIH/cypher-ray-models
python main.py
```

**2. Test Binary Analysis**:
```bash
curl -X POST http://localhost:5000/analyze -F file=@P_2_S_8.bin
```

**3. Check Response**:
```bash
# Should see in logs:
INFO | ✅ Injected Angr metadata: Linux AMD64 (432380 bytes)
```

**4. Verify Frontend Display**:
- **File Type**: Should show "Linux AMD64" (not "unknown")
- **Size**: Should show "432 KB" (not "N/A")
- **Architecture**: Should show "AMD64" (not "unknown")
- **MD5**: Should show actual hash (not "not_computed")
- **SHA-256**: Should show actual hash (not "not_computed")

---

## Why This Happened

Claude's final synthesis prompt says:
> For numeric fields (size), use 0 if not available (NOT "not_computed")

But Claude sometimes ignores this and returns `"size": "not_computed"` (string), which causes backend to fail parsing and default to "N/A".

**Solution**: Don't trust Claude for metadata. Always inject real Angr values after synthesis.

---

## Files Modified

1. **src/core/analysis_pipeline.py** (Lines 750-770)
   - Added metadata injection after final synthesis
   - Ensures proper field names for backend compatibility
   - Type-safe size handling (always number)

**Total Changes**: 1 file, ~20 lines added

---

## Backward Compatibility

✅ **Maintained**: Both old and new field names supported
- Old: `format`, `size`
- New: `file_type`, `size_bytes`
- Backend handles both via fallback: `fileMetadata.format || fileMetadata.file_type`

✅ **Type Safety**: Backend has safeguards for string → number conversion
```javascript
size_bytes: typeof fileMetadata.size === "number" ? fileMetadata.size :
            parseInt(fileMetadata.size_bytes || 0, 10) || 0
```

---

## Status

✅ **Analysis Working**: 8 algorithms, 11 YARA matches, 5 vulnerabilities detected
✅ **Logging Clean**: No CFGFast spam
✅ **Metadata Fixed**: Real Angr values now injected into response
⏳ **Pending Test**: Restart service and verify frontend display

**Next Action**: Test with binary to confirm metadata appears in frontend
