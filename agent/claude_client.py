"""
Thin wrapper around the Anthropic SDK for single-turn prompt calls.
"""

import os

import anthropic

MODEL   = "claude-opus-4-6"
MAX_TOKENS = 4096


def call(system_prompt: str, user_message: str) -> str:
    """
    Send a single-turn message to Claude and return the text response.

    Reads ANTHROPIC_API_KEY from the environment.
    Raises RuntimeError if the key is missing.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError(
            "ANTHROPIC_API_KEY environment variable is not set."
        )

    client = anthropic.Anthropic(api_key=api_key)
    message = client.messages.create(
        model=MODEL,
        max_tokens=MAX_TOKENS,
        system=system_prompt,
        messages=[{"role": "user", "content": user_message}],
    )
    return message.content[0].text
