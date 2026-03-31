"""Tests for agent/llm_client.py — unified LLM interface."""

import json
import os
from unittest.mock import MagicMock, patch

import pytest

from agent.llm_client import _call_claude, _call_openai, call


# ---------------------------------------------------------------------------
# test_call_claude — mock anthropic inside _call_claude
# ---------------------------------------------------------------------------

def test_call_claude(monkeypatch):
    """_call_claude returns the text from the Claude API response."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    mock_msg = MagicMock()
    mock_msg.content = [MagicMock(text="response text")]

    mock_client = MagicMock()
    mock_client.messages.create.return_value = mock_msg

    mock_anthropic = MagicMock()
    mock_anthropic.Anthropic.return_value = mock_client

    with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
        result = _call_claude("system prompt", "user message")

    assert result == "response text"
    mock_anthropic.Anthropic.assert_called_once_with(api_key="test-key")
    mock_client.messages.create.assert_called_once()


# ---------------------------------------------------------------------------
# test_call_openai — mock urllib.request.urlopen
# ---------------------------------------------------------------------------

def test_call_openai(monkeypatch):
    """_call_openai returns the content from the OpenAI API response."""
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps({
        "choices": [{"message": {"content": "gpt response"}}]
    }).encode()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_resp):
        result = _call_openai("system prompt", "user message")

    assert result == "gpt response"


# ---------------------------------------------------------------------------
# test_call_routes_to_claude
# ---------------------------------------------------------------------------

def test_call_routes_to_claude(monkeypatch):
    """call() with provider='claude' delegates to _call_claude."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    with patch("agent.llm_client._call_claude", return_value="claude result") as mock_claude:
        result = call("sys", "usr", provider="claude")

    mock_claude.assert_called_once_with("sys", "usr")
    assert result == "claude result"


# ---------------------------------------------------------------------------
# test_call_routes_to_openai
# ---------------------------------------------------------------------------

def test_call_routes_to_openai(monkeypatch):
    """call() with provider='openai' delegates to _call_openai."""
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    with patch("agent.llm_client._call_openai", return_value="openai result") as mock_openai:
        result = call("sys", "usr", provider="openai")

    mock_openai.assert_called_once_with("sys", "usr")
    assert result == "openai result"


# ---------------------------------------------------------------------------
# test_call_gpt_alias
# ---------------------------------------------------------------------------

def test_call_gpt_alias(monkeypatch):
    """call() with provider='gpt' also routes to _call_openai."""
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    with patch("agent.llm_client._call_openai", return_value="gpt result") as mock_openai:
        result = call("sys", "usr", provider="gpt")

    mock_openai.assert_called_once_with("sys", "usr")
    assert result == "gpt result"


# ---------------------------------------------------------------------------
# test_unsupported_provider
# ---------------------------------------------------------------------------

def test_unsupported_provider():
    """call() with an unsupported provider raises RuntimeError."""
    with pytest.raises(RuntimeError, match="Unsupported LLM provider: gemini"):
        call("sys", "usr", provider="gemini")


# ---------------------------------------------------------------------------
# test_missing_claude_key
# ---------------------------------------------------------------------------

def test_missing_claude_key(monkeypatch):
    """_call_claude raises RuntimeError when ANTHROPIC_API_KEY is missing."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
        _call_claude("sys", "usr")


# ---------------------------------------------------------------------------
# test_missing_openai_key
# ---------------------------------------------------------------------------

def test_missing_openai_key(monkeypatch):
    """_call_openai raises RuntimeError when OPENAI_API_KEY is missing."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    with pytest.raises(RuntimeError, match="OPENAI_API_KEY"):
        _call_openai("sys", "usr")


# ---------------------------------------------------------------------------
# test_claude_client_backward_compat
# ---------------------------------------------------------------------------

def test_claude_client_backward_compat():
    """claude_client.call() delegates to llm_client._call_claude."""
    from agent import claude_client

    with patch("agent.llm_client._call_claude", return_value="delegated") as mock_claude:
        result = claude_client.call("sys", "usr")

    mock_claude.assert_called_once_with("sys", "usr")
    assert result == "delegated"


# ---------------------------------------------------------------------------
# test_model_from_env
# ---------------------------------------------------------------------------

def test_model_from_env(monkeypatch):
    """_call_claude uses PATCHPILOT_CLAUDE_MODEL env var when set."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("PATCHPILOT_CLAUDE_MODEL", "claude-custom-model")

    mock_msg = MagicMock()
    mock_msg.content = [MagicMock(text="custom model response")]

    mock_client = MagicMock()
    mock_client.messages.create.return_value = mock_msg

    mock_anthropic = MagicMock()
    mock_anthropic.Anthropic.return_value = mock_client

    with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
        result = _call_claude("system", "user")

    assert result == "custom model response"
    call_kwargs = mock_client.messages.create.call_args
    assert call_kwargs.kwargs.get("model") == "claude-custom-model" or (
        len(call_kwargs.args) > 0 and call_kwargs.args[0] == "claude-custom-model"
    ) or call_kwargs[1].get("model") == "claude-custom-model"
