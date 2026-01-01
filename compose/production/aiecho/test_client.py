"""
Test client for the OpenAI API emulation server
Install: pip install openai
"""
from openai import OpenAI
import sys

# Configure the client to use your mock server
client = OpenAI(
    api_key="sk-test-mock-api-key-12345",
    base_url="http://localhost:8000/v1"
)

def test_list_models():
    """Test listing available models"""
    print("\n=== Testing List Models ===")
    try:
        models = client.models.list()
        print(f"✓ Available models:")
        for model in models.data:
            print(f"  - {model.id}")
    except Exception as e:
        print(f"✗ Error: {e}")

def test_valid_chat(model="qwen3-32b", prompt="Hello, how are you?"):
    """Test chat completion with a valid model"""
    print(f"\n=== Testing Chat with {model} ===")
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        print(f"✓ Response: {response.choices[0].message.content}")
        print(f"  Tokens used: {response.usage.total_tokens}")
    except Exception as e:
        print(f"✗ Error: {e}")

def test_streaming_chat(model="deepseek-r1", prompt="Count to 5"):
    """Test streaming chat completion"""
    print(f"\n=== Testing Streaming Chat with {model} ===")
    try:
        stream = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            stream=True
        )
        print("✓ Streaming response: ", end="", flush=True)
        for chunk in stream:
            if chunk.choices[0].delta.content:
                print(chunk.choices[0].delta.content, end="", flush=True)
        print()
    except Exception as e:
        print(f"✗ Error: {e}")

def test_invalid_model():
    """Test with an invalid model (should fail)"""
    print("\n=== Testing Invalid Model ===")
    try:
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "Hello"}]
        )
        print(f"✗ Should have failed but got: {response.choices[0].message.content}")
    except Exception as e:
        print(f"✓ Expected error: {e}")

def test_invalid_api_key():
    """Test with an invalid API key (should fail)"""
    print("\n=== Testing Invalid API Key ===")
    try:
        bad_client = OpenAI(
            api_key="wrong-key",
            base_url="http://localhost:8000/v1"
        )
        response = bad_client.chat.completions.create(
            model="qwen3-32b",
            messages=[{"role": "user", "content": "Hello"}]
        )
        print(f"✗ Should have failed but got: {response.choices[0].message.content}")
    except Exception as e:
        print(f"✓ Expected error: {e}")

def test_conversation():
    """Test multi-turn conversation"""
    print("\n=== Testing Multi-turn Conversation ===")
    try:
        messages = [
            {"role": "user", "content": "First question"},
            {"role": "assistant", "content": "First answer"},
            {"role": "user", "content": "Second question"}
        ]
        response = client.chat.completions.create(
            model="llama-3.3-70b-instruct",
            messages=messages
        )
        print(f"✓ Response: {response.choices[0].message.content}")
    except Exception as e:
        print(f"✗ Error: {e}")

if __name__ == "__main__":
    print("OpenAI API Emulation Server Test Suite")
    print("=" * 50)
    
    # Run all tests
    test_list_models()
    test_valid_chat()
    test_streaming_chat()
    test_conversation()
    test_invalid_model()
    test_invalid_api_key()
    
    # Test all models
    print("\n=== Testing All Available Models ===")
    for model in ["qwen3-32b", "deepseek-r1", "llama-3.3-70b-instruct"]:
        test_valid_chat(model, f"Test message for {model}")
    
    print("\n" + "=" * 50)
    print("Test suite completed!")