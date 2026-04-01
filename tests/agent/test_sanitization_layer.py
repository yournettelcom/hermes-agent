"""Tests for sanitization_layer module."""

import pytest
from agent.sanitization_layer import (
    DeterministicSanitizer,
    SanitizationPattern,
    get_sanitizer,
)


class TestSanitizationPattern:
    """Test individual sanitization patterns."""

    def test_pattern_apply_basic(self):
        """Test basic pattern matching and replacement."""
        pattern = SanitizationPattern(
            name="test",
            regex=r"secret_\w+",
            replacement="[REDACTED]"
        )
        pattern.compile()
        
        result = pattern.apply("my secret_key is here")
        assert result == "my [REDACTED] is here"

    def test_pattern_case_insensitive(self):
        """Test case-insensitive matching."""
        pattern = SanitizationPattern(
            name="test",
            regex=r"API_KEY",
            replacement="[REDACTED]"
        )
        pattern.compile()
        
        result = pattern.apply("api_key and API_KEY and Api_Key")
        assert result.count("[REDACTED]") == 3

    def test_pattern_disabled(self):
        """Test that disabled patterns don't apply."""
        pattern = SanitizationPattern(
            name="test",
            regex=r"secret",
            replacement="[REDACTED]",
            enabled=False
        )
        pattern.compile()
        
        result = pattern.apply("secret data")
        assert result == "secret data"


class TestDeterministicSanitizer:
    """Test DeterministicSanitizer class."""

    def test_mode_off(self):
        """Test 'off' mode does no sanitization."""
        sanitizer = DeterministicSanitizer(mode="off")
        text = "sk-abc123def456"
        
        result, matches = sanitizer.sanitize_text(text)
        assert result == text
        assert matches == 0

    def test_mode_moderate_api_keys(self):
        """Test moderate mode catches API keys."""
        sanitizer = DeterministicSanitizer(mode="moderate")
        
        # OpenAI key
        result, _ = sanitizer.sanitize_text("My key is sk-abc1234567890abcdef")
        assert "[REDACTED" in result
        assert "sk-abc" not in result

    def test_mode_strict_includes_ips(self):
        """Test strict mode includes IP redaction."""
        sanitizer = DeterministicSanitizer(mode="strict")
        
        result, _ = sanitizer.sanitize_text("Connect to 192.168.1.100 server")
        assert "[REDACTED" in result
        assert "192.168.1.100" not in result

    def test_sanitize_message_dict(self):
        """Test sanitizing message dictionaries."""
        sanitizer = DeterministicSanitizer(mode="moderate")
        
        message = {
            "role": "user",
            "content": "My API key is sk-12345678901234567890"
        }
        
        result = sanitizer.sanitize_message(message)
        assert "sk-12345" not in result["content"]
        assert "[REDACTED" in result["content"]

    def test_sanitize_conversation(self):
        """Test sanitizing full conversation."""
        sanitizer = DeterministicSanitizer(mode="moderate")
        
        messages = [
            {"role": "system", "content": "You know password=secret123"},
            {"role": "user", "content": "Help me with this"},
        ]
        
        result = sanitizer.sanitize_conversation(messages)
        
        content_str = "".join([m["content"] for m in result])
        assert "password=" not in content_str or "[REDACTED" in content_str


class TestGetSanitizer:
    """Test get_sanitizer factory function."""

    def test_disabled_by_default(self):
        """Test that sanitization is disabled by default."""
        config = {"sanitization": {"enabled": False}}
        sanitizer = get_sanitizer(config)
        
        assert sanitizer.mode == "off"

    def test_load_from_config(self):
        """Test loading from config dict."""
        config = {
            "sanitization": {
                "enabled": True,
                "mode": "moderate"
            }
        }
        sanitizer = get_sanitizer(config)
        
        assert sanitizer.mode == "moderate"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
