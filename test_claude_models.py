#!/usr/bin/env python3
"""Test which Claude models are actually available with your API key."""

import os
from anthropic import Anthropic

# Test models to try
MODELS_TO_TEST = [
    "claude-3-5-sonnet-20241022",
    "claude-3-5-sonnet-20240620",
    "claude-3-opus-20240229",
    "claude-3-sonnet-20240229",
    "claude-3-haiku-20240307",
    "claude-3-5-haiku-20241022",
    # Legacy names
    "claude-3-5-sonnet-latest",
    "claude-3-opus-latest",
    "claude-3-sonnet-latest",
    "claude-3-haiku-latest",
]

def test_model(client: Anthropic, model: str) -> bool:
    """Test if a model works by making a simple API call."""
    try:
        response = client.messages.create(
            model=model,
            max_tokens=10,
            messages=[{"role": "user", "content": "Hi"}]
        )
        return True
    except Exception as e:
        error_str = str(e)
        if "not_found_error" in error_str or "404" in error_str:
            return False
        elif "invalid_api_key" in error_str:
            print(f"❌ API KEY INVALID!")
            return False
        else:
            print(f"⚠️  {model}: {error_str[:100]}")
            return False

def main():
    api_key = os.getenv('ANTHROPIC_API_KEY')
    if not api_key:
        print("❌ ANTHROPIC_API_KEY not set!")
        return
    
    print("🔍 Testing Claude models with your API key...\n")
    client = Anthropic(api_key=api_key)
    
    working_models = []
    
    for model in MODELS_TO_TEST:
        print(f"Testing {model}...", end=" ")
        if test_model(client, model):
            print("✅ WORKS!")
            working_models.append(model)
        else:
            print("❌ 404 Not Found")
    
    print("\n" + "="*60)
    if working_models:
        print("✅ WORKING MODELS:")
        for model in working_models:
            print(f"   - {model}")
    else:
        print("❌ NO WORKING MODELS FOUND!")
        print("\n🔍 Possible issues:")
        print("   1. API key is invalid or expired")
        print("   2. API key doesn't have access to Claude models")
        print("   3. Wrong API endpoint (check region)")
    print("="*60)

if __name__ == "__main__":
    main()
