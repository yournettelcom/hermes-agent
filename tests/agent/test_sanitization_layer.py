"""Tests for sanitization_layer module."""

import pytest
from agent.sanitization_layer import (
    DeterministicSanitizer,
    SanitizationPattern,
    get_sanitizer,
)


class TestSanitizationPattern:
    def test_pattern_apply_basic(self):
        pattern = SanitizationPattern(name="test", regex=r"secret_\w+", replacement="[REDACTED]")
        pattern.compile()
        assert pattern.apply("my secret_key is here") == "my [REDACTED] is here"

    def test_pattern_disabled(self):
        pattern = SanitizationPattern(name="test", regex=r"secret", replacement="[REDACTED]", enabled=False)
        pattern.compile()
        assert pattern.apply("secret data") == "secret data"


class TestDeterministicSanitizer:
    def test_mode_off(self):
        sanitizer = DeterministicSanitizer(mode="off")
        result, matches = sanitizer.sanitize_text("sk-abc123def456")
        assert matches == 0

    def test_mode_moderate_aws_key(self):
        sanitizer = DeterministicSanitizer(mode="moderate")
        result, _ = sanitizer.sanitize_text("key is AKIAIOSFODNN7EXAMPLE")
        assert "[REDACTED" in result
        assert "AKIAIOSFODNN7EXAMPLE" not in result

    def test_mode_moderate_openai_key(self):
        sanitizer = DeterministicSanitizer(mode="moderate")
        # OpenAI key needs 40+ chars after sk-
        key = "sk-" + "a" * 45
        result, _ = sanitizer.sanitize_text(f"My key is {key}")
        assert "[REDACTED" in result

    def test_mode_strict_includes_ips(self):
        sanitizer = DeterministicSanitizer(mode="strict")
        result, _ = sanitizer.sanitize_text("Connect to 192.168.1.100 server")
        assert "192.168.1.100" not in result

    def test_sanitize_message_dict(self):
        sanitizer = DeterministicSanitizer(mode="moderate")
        key = "AKIAIOSFODNN7EXAMPLE"
        message = {"role": "user", "content": f"My AWS key is {key}"}
        result = sanitizer.sanitize_message(message)
        assert key not in result["content"]
        assert "[REDACTED" in result["content"]

    def test_sanitize_conversation(self):
        sanitizer = DeterministicSanitizer(mode="moderate")
        messages = [
            {"role": "system", "content": "key: AKIAIOSFODNN7EXAMPLE"},
            {"role": "user", "content": "Help me"},
        ]
        result = sanitizer.sanitize_conversation(messages)
        assert "AKIAIOSFODNN7EXAMPLE" not in result[0]["content"]

    def test_mode_off_no_changes(self):
        sanitizer = DeterministicSanitizer(mode="off")
        messages = [{"role": "user", "content": "AKIAIOSFODNN7EXAMPLE"}]
        result = sanitizer.sanitize_conversation(messages)
        assert result == messages


class TestGetSanitizer:
    def test_disabled_by_default(self):
        config = {"sanitization": {"enabled": False}}
        assert get_sanitizer(config).mode == "off"

    def test_load_from_config(self):
        config = {"sanitization": {"enabled": True, "mode": "moderate"}}
        assert get_sanitizer(config).mode == "moderate"

    def test_empty_config(self):
        assert get_sanitizer({}).mode == "off"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
