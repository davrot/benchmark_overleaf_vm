from flask import Flask, request, jsonify, Response
import json
import time
from datetime import datetime

app = Flask(__name__)

# Configuration
VALID_API_KEY = "sk-test-mock-api-key-12345"
VALID_MODELS = [
    "qwen3-32b",
    "deepseek-r1",
    "llama-3.3-70b-instruct"
]

def verify_api_key():
    """Verify the API key from request headers"""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return False, {
            "error": {
                "message": "You didn't provide an API key. You need to provide your API key in an Authorization header using Bearer auth (i.e. Authorization: Bearer YOUR_KEY)",
                "type": "invalid_request_error",
                "param": None,
                "code": None
            }
        }
    
    api_key = auth_header[7:]  # Remove "Bearer " prefix
    if api_key != VALID_API_KEY:
        return False, {
            "error": {
                "message": "Incorrect API key provided. You can find your API key at https://platform.openai.com/account/api-keys.",
                "type": "invalid_request_error",
                "param": None,
                "code": "invalid_api_key"
            }
        }
    
    return True, None

@app.route("/v1/models", methods=["GET"])
def list_models():
    """List available models"""
    is_valid, error = verify_api_key()
    if not is_valid:
        return jsonify(error), 401
    
    models_list = []
    for model_id in VALID_MODELS:
        models_list.append({
            "id": model_id,
            "object": "model",
            "created": int(time.time()),
            "owned_by": "organization-owner"
        })
    
    return jsonify({
        "object": "list",
        "data": models_list
    })

@app.route("/v1/chat/completions", methods=["POST"])
def chat_completions():
    """Handle chat completion requests"""
    is_valid, error = verify_api_key()
    if not is_valid:
        return jsonify(error), 401
    
    data = request.get_json()
    
    # Validate model
    model = data.get("model")
    if not model:
        return jsonify({
            "error": {
                "message": "you must provide a model parameter",
                "type": "invalid_request_error",
                "param": None,
                "code": None
            }
        }), 400
    
    if model not in VALID_MODELS:
        return jsonify({
            "error": {
                "message": f"The model `{model}` does not exist",
                "type": "invalid_request_error",
                "param": None,
                "code": "model_not_found"
            }
        }), 404
    
    # Extract messages
    messages = data.get("messages", [])
    if not messages:
        return jsonify({
            "error": {
                "message": "'messages' is a required property",
                "type": "invalid_request_error",
                "param": None,
                "code": None
            }
        }), 400
    
    # Get the last user message for the echo
    last_message = ""
    for msg in reversed(messages):
        if msg.get("role") == "user":
            last_message = msg.get("content", "")
            break
    
    # Create echo response
    echo_content = f"Echo from {model}: {last_message}"
    
    # Check if streaming is requested
    stream = data.get("stream", False)
    
    if stream:
        return stream_response(model, echo_content)
    else:
        return regular_response(model, echo_content)

def regular_response(model, content):
    """Generate a regular (non-streaming) response"""
    response = {
        "id": f"chatcmpl-{int(time.time())}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": content
                },
                "finish_reason": "stop"
            }
        ],
        "usage": {
            "prompt_tokens": 10,
            "completion_tokens": len(content.split()),
            "total_tokens": 10 + len(content.split())
        }
    }
    return jsonify(response)

def stream_response(model, content):
    """Generate a streaming response"""
    def generate():
        # Initial chunk
        chunk_id = f"chatcmpl-{int(time.time())}"
        
        # Send content word by word
        words = content.split()
        for i, word in enumerate(words):
            chunk = {
                "id": chunk_id,
                "object": "chat.completion.chunk",
                "created": int(time.time()),
                "model": model,
                "choices": [
                    {
                        "index": 0,
                        "delta": {
                            "content": word + (" " if i < len(words) - 1 else "")
                        },
                        "finish_reason": None
                    }
                ]
            }
            yield f"data: {json.dumps(chunk)}\n\n"
        
        # Final chunk
        final_chunk = {
            "id": chunk_id,
            "object": "chat.completion.chunk",
            "created": int(time.time()),
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "delta": {},
                    "finish_reason": "stop"
                }
            ]
        }
        yield f"data: {json.dumps(final_chunk)}\n\n"
        yield "data: [DONE]\n\n"
    
    return Response(generate(), mimetype="text/event-stream")

@app.errorhandler(404)
def not_found(e):
    return jsonify({
        "error": {
            "message": "Invalid URL",
            "type": "invalid_request_error",
            "param": None,
            "code": None
        }
    }), 404

if __name__ == "__main__":
    print(f"Starting OpenAI API Emulation Server")
    print(f"Valid API Key: {VALID_API_KEY}")
    print(f"Valid Models: {', '.join(VALID_MODELS)}")
    print(f"Server running on http://0.0.0.0:8000")
    app.run(host="0.0.0.0", port=8000, debug=True)