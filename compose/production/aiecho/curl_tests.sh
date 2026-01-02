#!/bin/bash

# OpenAI API Mock Server - cURL Test Suite
# Make executable: chmod +x test_api.sh

API_KEY="sk-test-mock-api-key-12345"
BASE_URL="http://localhost:8000/v1"

echo "======================================"
echo "OpenAI API Mock Server - cURL Tests"
echo "======================================"

# Test 1: List Models
echo ""
echo "=== Test 1: List Available Models ==="
curl -s -X GET "${BASE_URL}/models" \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" | jq '.'

# Test 2: Valid Chat Completion
echo ""
echo "=== Test 2: Chat Completion (qwen3-32b) ==="
curl -s -X POST "${BASE_URL}/chat/completions" \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "qwen3-32b",
    "messages": [
      {"role": "user", "content": "Hello, how are you?"}
    ]
  }' | jq '.'

# Test 3: Different Model
echo ""
echo "=== Test 3: Chat Completion (deepseek-r1) ==="
curl -s -X POST "${BASE_URL}/chat/completions" \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "deepseek-r1",
    "messages": [
      {"role": "user", "content": "What is 2+2?"}
    ]
  }' | jq '.choices[0].message.content'

# Test 4: Llama Model
echo ""
echo "=== Test 4: Chat Completion (llama-3.3-70b-instruct) ==="
curl -s -X POST "${BASE_URL}/chat/completions" \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "llama-3.3-70b-instruct",
    "messages": [
      {"role": "user", "content": "Write a haiku about coding"}
    ]
  }' | jq '.choices[0].message.content'

# Test 5: Multi-turn Conversation
echo ""
echo "=== Test 5: Multi-turn Conversation ==="
curl -s -X POST "${BASE_URL}/chat/completions" \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "qwen3-32b",
    "messages": [
      {"role": "user", "content": "My name is Alice"},
      {"role": "assistant", "content": "Hello Alice!"},
      {"role": "user", "content": "What is my name?"}
    ]
  }' | jq '.choices[0].message.content'

# Test 6: Streaming Response
echo ""
echo "=== Test 6: Streaming Chat Completion ==="
curl -s -X POST "${BASE_URL}/chat/completions" \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "deepseek-r1",
    "messages": [
      {"role": "user", "content": "Count from 1 to 5"}
    ],
    "stream": true
  }'

# Test 7: Invalid Model (should fail)
echo ""
echo ""
echo "=== Test 7: Invalid Model (Expected to Fail) ==="
curl -s -X POST "${BASE_URL}/chat/completions" \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4",
    "messages": [
      {"role": "user", "content": "Hello"}
    ]
  }' | jq '.'

# Test 8: Invalid API Key (should fail)
echo ""
echo "=== Test 8: Invalid API Key (Expected to Fail) ==="
curl -s -X POST "${BASE_URL}/chat/completions" \
  -H "Authorization: Bearer wrong-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "qwen3-32b",
    "messages": [
      {"role": "user", "content": "Hello"}
    ]
  }' | jq '.'

# Test 9: Missing API Key (should fail)
echo ""
echo "=== Test 9: Missing API Key (Expected to Fail) ==="
curl -s -X POST "${BASE_URL}/chat/completions" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "qwen3-32b",
    "messages": [
      {"role": "user", "content": "Hello"}
    ]
  }' | jq '.'

# Test 10: Missing Model Parameter (should fail)
echo ""
echo "=== Test 10: Missing Model Parameter (Expected to Fail) ==="
curl -s -X POST "${BASE_URL}/chat/completions" \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "messages": [
      {"role": "user", "content": "Hello"}
    ]
  }' | jq '.'

# Test 11: Invalid Endpoint (should fail)
echo ""
echo "=== Test 11: Invalid Endpoint (Expected to Fail) ==="
curl -s -X GET "${BASE_URL}/invalid" \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" | jq '.'

echo "======================================"
echo "Test Suite Completed!"
echo "======================================"
