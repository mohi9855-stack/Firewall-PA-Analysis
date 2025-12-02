"""
LLM Configuration - Local OpenAI-Compatible API Configuration
"""
import os
from typing import Optional

# Local OpenAI-Compatible API Configuration (e.g., LM Studio, LocalAI, etc.)
LLM_MODEL_NAME = "openai/gpt-oss-20b"  # Local model name
# The model name should match what your local server reports at http://localhost:1234/v1/models

LLM_BASE_URL = os.getenv("LLM_BASE_URL", "http://localhost:1234/v1")  # Local OpenAI-compatible API base URL (LM Studio uses /v1 endpoint)
LLM_API_KEY = os.getenv("LLM_API_KEY", "not-needed")  # Local models typically don't need a real API key, but the client requires one

# LLM Request Configuration
LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.7"))
LLM_MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", "2048"))  # Reduced to fit within 4096 token context window (leaving room for prompt)
LLM_TIMEOUT = int(os.getenv("LLM_TIMEOUT", "300"))  # Timeout in seconds

# Chunking Configuration (for large prompts that exceed context window)
LLM_MAX_PROMPT_CHARS = int(os.getenv("LLM_MAX_PROMPT_CHARS", "12000"))  # Safe limit for 4096 token context (~3000 tokens)
LLM_CHUNK_SIZE = int(os.getenv("LLM_CHUNK_SIZE", "50"))  # Number of rules per chunk

# Excel File Configuration
EXCEL_FILE_NAME = "Final_output_scored_static.xlsx"

def get_llm_config() -> dict:
    """
    Get all LLM configuration as a dictionary.
    """
    return {
        "model": LLM_MODEL_NAME,
        "base_url": LLM_BASE_URL,
        "api_key": LLM_API_KEY,
        "temperature": LLM_TEMPERATURE,
        "max_tokens": LLM_MAX_TOKENS,
        "timeout": LLM_TIMEOUT,
    }

