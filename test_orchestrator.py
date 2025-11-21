#!/usr/bin/env python3
"""
Test script for Multi-Model Orchestrator.
Tests model selection, caching, cost tracking, and parallel analysis.
"""

import asyncio
import json
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

from src.models.multi_model_orchestrator import MultiModelOrchestrator
from src.utils.logger import get_logger

logger = get_logger(__name__)


async def test_quick_classification():
    """Test quick classification with cheapest model."""
    print("\n" + "="*60)
    print("TEST 1: Quick Classification (GPT-4o-mini)")
    print("="*60)
    
    orchestrator = MultiModelOrchestrator()
    
    query = """
Is this code cryptographic?

```c
void process(uint8_t *data, int len) {
    for (int i = 0; i < len; i++) {
        data[i] ^= 0x42;
    }
}
```

Answer in JSON: {"is_crypto": true/false, "confidence": 0.0-1.0, "reason": "..."}
"""
    
    result = await orchestrator.analyze(
        query=query,
        context={},
        analysis_type='quick_classify'
    )
    
    print(f"✅ Model: {result['model']}")
    print(f"✅ Provider: {result['provider']}")
    print(f"✅ Cost: ${result['cost']:.6f}")
    print(f"✅ Duration: {result['duration']:.2f}s")
    print(f"✅ Response preview: {result['content'][:200]}...")
    
    return result


async def test_main_analysis():
    """Test main analysis with GPT-4o."""
    print("\n" + "="*60)
    print("TEST 2: Main Analysis (GPT-4o)")
    print("="*60)
    
    orchestrator = MultiModelOrchestrator()
    
    query = """
Analyze this AES encryption function for correctness and vulnerabilities:

```c
void aes_encrypt(uint8_t *state, uint8_t *key) {
    // S-box lookup
    for (int i = 0; i < 16; i++) {
        state[i] = sbox[state[i]];
    }
    
    // Shift rows
    shift_rows(state);
    
    // Mix columns
    mix_columns(state);
    
    // Add round key
    for (int i = 0; i < 16; i++) {
        state[i] ^= key[i];
    }
}
```

Provide detailed analysis with potential issues.
"""
    
    result = await orchestrator.analyze(
        query=query,
        context={"algorithm": "AES", "operations": ["substitute", "shift", "mix", "xor"]},
        analysis_type='main_analysis'
    )
    
    print(f"✅ Model: {result['model']}")
    print(f"✅ Provider: {result['provider']}")
    print(f"✅ Cost: ${result['cost']:.6f}")
    print(f"✅ Response length: {len(result['content'])} chars")
    print(f"✅ Response preview: {result['content'][:300]}...")
    
    return result


async def test_caching():
    """Test caching mechanism."""
    print("\n" + "="*60)
    print("TEST 3: Caching Mechanism")
    print("="*60)
    
    orchestrator = MultiModelOrchestrator()
    
    query = "What is AES encryption?"
    context = {"topic": "cryptography"}
    
    # First call (should hit API)
    print("\n📡 First call (should hit API)...")
    result1 = await orchestrator.analyze(query, context, 'quick_classify')
    cost1 = result1['cost']
    print(f"✅ Cost: ${cost1:.6f}")
    
    # Second call (should use cache)
    print("\n💾 Second call (should use cache)...")
    result2 = await orchestrator.analyze(query, context, 'quick_classify')
    cost2 = result2.get('cost', 0)
    print(f"✅ Cost: ${cost2:.6f}")
    
    # Verify responses are identical
    if result1['content'] == result2['content']:
        print("✅ Cache working! Same response returned")
    else:
        print("❌ Cache issue: Different responses")
    
    return result1, result2


async def test_parallel_analysis():
    """Test parallel analysis."""
    print("\n" + "="*60)
    print("TEST 4: Parallel Analysis")
    print("="*60)
    
    orchestrator = MultiModelOrchestrator()
    
    tasks = [
        {
            "query": "Is XOR operation cryptographic?",
            "context": {"operation": "xor"},
            "analysis_type": "quick_classify"
        },
        {
            "query": "Is bit rotation cryptographic?",
            "context": {"operation": "rotation"},
            "analysis_type": "quick_classify"
        },
        {
            "query": "Is modular arithmetic cryptographic?",
            "context": {"operation": "modular"},
            "analysis_type": "quick_classify"
        }
    ]
    
    print(f"\n⚡ Running {len(tasks)} tasks in parallel...")
    results = await orchestrator.parallel_analyze(tasks)
    
    print(f"✅ Completed {len(results)} tasks")
    for i, result in enumerate(results, 1):
        print(f"  Task {i}: {result['model']} - ${result['cost']:.6f}")
    
    total_cost = sum(r['cost'] for r in results)
    print(f"\n✅ Total cost: ${total_cost:.6f}")
    
    return results


async def test_fallback_mechanism():
    """Test fallback when model fails (simulated)."""
    print("\n" + "="*60)
    print("TEST 5: Fallback Mechanism")
    print("="*60)
    
    orchestrator = MultiModelOrchestrator()
    
    # Normal query that should work
    query = "Explain RSA encryption in one sentence."
    
    result = await orchestrator.analyze(
        query=query,
        context={},
        analysis_type='main_analysis',
        max_retries=2
    )
    
    print(f"✅ Successfully used: {result['model']}")
    print(f"✅ Response: {result['content'][:200]}...")
    
    return result


async def test_cost_tracking():
    """Test cost tracking and reporting."""
    print("\n" + "="*60)
    print("TEST 6: Cost Tracking & Reporting")
    print("="*60)
    
    orchestrator = MultiModelOrchestrator()
    
    # Make a few calls
    await orchestrator.analyze("Test 1", {}, 'quick_classify')
    await orchestrator.analyze("Test 2", {}, 'main_analysis')
    
    # Get cost summary
    summary = orchestrator.get_cost_summary()
    
    print(f"\n💰 Total Cost: ${summary['total_cost']:.4f}")
    print(f"\n📊 Cost by Provider:")
    for provider, cost in summary['cost_by_provider'].items():
        print(f"  {provider}: ${cost:.4f}")
    
    print(f"\n📊 Cost by Model:")
    for model, cost in summary['cost_by_model'].items():
        print(f"  {model}: ${cost:.4f}")
    
    print(f"\n📈 Token Usage:")
    token_usage = summary['token_usage']
    if isinstance(token_usage, dict):
        for key, value in token_usage.items():
            if isinstance(value, (int, float)):
                print(f"  {key}: {value:,}")
            else:
                print(f"  {key}: {value}")
    else:
        print(f"  {token_usage}")
    
    print(f"\n📊 Call Statistics:")
    stats = summary['call_statistics']
    print(f"  Total calls: {stats['total_calls']}")
    print(f"  Success rate: {stats['success_rate']:.1%}")
    print(f"  Average cost per call: ${stats['avg_cost_per_call']:.6f}")
    
    return summary


async def run_all_tests():
    """Run all orchestrator tests."""
    print("\n" + "🧪 "*20)
    print("MULTI-MODEL ORCHESTRATOR TEST SUITE")
    print("🧪 "*20)
    
    try:
        # Run tests
        await test_quick_classification()
        await test_main_analysis()
        await test_caching()
        await test_parallel_analysis()
        await test_fallback_mechanism()
        summary = await test_cost_tracking()
        
        # Final summary
        print("\n" + "="*60)
        print("✅ ALL TESTS PASSED!")
        print("="*60)
        print(f"\n💰 Session Total Cost: ${summary['total_cost']:.4f}")
        print(f"📞 Total API Calls: {summary['call_statistics']['total_calls']}")
        print(f"✅ Success Rate: {summary['call_statistics']['success_rate']:.1%}")
        
        # Export cost report
        orchestrator = MultiModelOrchestrator()
        report_path = orchestrator.cost_tracker.export_report()
        print(f"\n📄 Cost report saved to: {report_path}")
        
    except Exception as e:
        print(f"\n❌ TEST FAILED: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    # Run test suite
    asyncio.run(run_all_tests())
