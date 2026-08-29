"""
SecureLLM AI — Flask Server Backend

Orchestrates the prompt injection defense pipeline and calls the LLM (Gemini or Mock).
Supports bypass mode to demonstrate prompt injection vulnerability without the proxy.
"""

import os
from dotenv import load_dotenv
load_dotenv()  # Automatically loads GEMINI_API_KEY from .env file
from flask import Flask, request, jsonify, render_template
from secure_llm import SecureLLMProxy
from secure_llm.context_encapsulation import ContextBlock, TrustLevel
from secure_llm.llm_client import generate_llm_response, MOCK_SYSTEM_RULES

app = Flask(__name__)

# Cache of proxy instances by (intent_threshold, block_on_sanitizer, block_on_intent)
# to avoid retraining the model on every single keypress or request if settings are the same.
_proxy_cache = {}

def get_proxy(intent_threshold: float, block_on_sanitizer: bool, block_on_intent: bool) -> SecureLLMProxy:
    cache_key = (intent_threshold, block_on_sanitizer, block_on_intent)
    if cache_key not in _proxy_cache:
        # Create new proxy instance (will train its classifier on start)
        _proxy_cache[cache_key] = SecureLLMProxy(
            system_rules="", # We pass system rules per process call dynamically in build()
            intent_threshold=intent_threshold,
            block_on_sanitizer_high_severity=block_on_sanitizer,
            block_on_adversarial_intent=block_on_intent
        )
    return _proxy_cache[cache_key]

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/config")
def get_config():
    """Exposes non-secret config to the frontend (API key presence + default provider)."""
    api_key = os.environ.get("GEMINI_API_KEY", "")
    return jsonify({
        "has_api_key": bool(api_key),
        "api_key": api_key,           # sent over localhost only — safe for dev use
        "default_provider": "gemini" if api_key else "mock"
    })

@app.route("/api/process", methods=["POST"])
def process_prompt():
    data = request.json or {}
    
    system_rules = data.get("system_rules", MOCK_SYSTEM_RULES)
    user_input = data.get("user_input", "")
    tool_context_raw = data.get("tool_context", [])
    
    intent_threshold = float(data.get("intent_threshold", 0.5))
    block_on_sanitizer = bool(data.get("block_on_sanitizer", True))
    block_on_intent = bool(data.get("block_on_intent", True))
    
    provider = data.get("provider", "mock")
    model = data.get("model", "gemini-2.5-flash")
    api_key = data.get("api_key") or os.environ.get("GEMINI_API_KEY")
    
    bypass_proxy = bool(data.get("bypass_proxy", False))

    # Convert tool context to ContextBlock items
    tool_context = []
    for item in tool_context_raw:
        if item.get("content"):
            tool_context.append(
                ContextBlock(
                    trust_level=TrustLevel.TOOL_OUTPUT,
                    content=item.get("content"),
                    source=item.get("source")
                )
            )

    if bypass_proxy:
        # --- BYPASS MODE (Vulnerable Direct Path) ---
        # Construct a simple un-escaped prompt combining system rules and user input
        raw_prompt = f"System Rules:\n{system_rules}\n\nUser Input:\n{user_input}"
        if tool_context:
            tool_str = "\n\n".join([f"Tool Context (source={b.source}):\n{b.content}" for b in tool_context])
            raw_prompt = f"System Rules:\n{system_rules}\n\n{tool_str}\n\nUser Input:\n{user_input}"
        
        # Call the LLM directly
        llm_response = generate_llm_response(
            prompt=raw_prompt,
            api_key=api_key,
            provider=provider,
            model=model
        )
        
        return jsonify({
            "allowed": True,
            "bypass_active": True,
            "reason": "Proxy bypassed by user.",
            "final_prompt": raw_prompt,
            "llm_response": llm_response,
            "sanitizer": {
                "blocked": False,
                "findings": [],
                "cleaned_text": user_input
            },
            "intent": {
                "label": "bypassed",
                "confidence": 0.0,
                "adversarial_score": 0.0
            }
        })

    # --- SECURE MODE (Proxy Active) ---
    proxy = get_proxy(intent_threshold, block_on_sanitizer, block_on_intent)
    
    # We update the proxy's system rules dynamically for this run
    proxy.system_rules = system_rules
    
    # Execute defense pipeline
    result = proxy.process(user_input, tool_context=tool_context)
    
    # Package details for the frontend
    sanitizer_data = {
        "blocked": result.sanitization.blocked,
        "cleaned_text": result.sanitization.cleaned_text,
        "findings": [
            {
                "rule_name": f.rule_name,
                "severity": f.severity.value,
                "matched_text": f.matched_text,
                "description": f.description
            } for f in result.sanitization.findings
        ]
    }
    
    intent_data = {
        "label": result.intent.label if result.intent else "skipped",
        "confidence": result.intent.confidence if result.intent else 0.0,
        "adversarial_score": result.intent.adversarial_score if result.intent else 0.0
    } if result.intent else None
    
    llm_response = None
    if result.allowed:
        # Call the LLM using the constructed final prompt
        llm_response = generate_llm_response(
            prompt=result.final_prompt,
            api_key=api_key,
            provider=provider,
            model=model
        )
        
    return jsonify({
        "allowed": result.allowed,
        "bypass_active": False,
        "reason": result.reason,
        "final_prompt": result.final_prompt,
        "llm_response": llm_response,
        "sanitizer": sanitizer_data,
        "intent": intent_data
    })

if __name__ == "__main__":
    app.run(debug=True, port=5000)
