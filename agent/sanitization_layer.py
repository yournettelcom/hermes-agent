"""
Deterministic Sanitization Layer for Hermes Agent

OPTIONAL hook to sanitize sensitive data before LLM context injection.
Prevents accidental exfiltration of secrets, PII, and sensitive code.

Design:
- Opt-in: Defaults to OFF (backward compatible)
- Configurable: User can define patterns
- Deterministic: Same input = same output
- Non-destructive to memory: Only affects LLM context, not storage

Usage in config.yaml:
    sanitization:
        enabled: true
        mode: "strict"  # "off" | "moderate" | "strict"
        custom_patterns:
            - name: "company_key"
              regex: "COMPANY_[A-Z0-9]{32}"
              replacement: "[REDACTED_COMPANY_KEY]"
"""

import re
import logging
from typing import Dict, List, Optional, Pattern, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class SanitizationPattern:
    """Single sanitization pattern (name, regex, replacement)."""
    
    name: str
    regex: str
    replacement: str
    enabled: bool = True
    compiled_pattern: Optional[Pattern] = None
    match_count: int = field(default=0, init=False)
    
    def compile(self) -> None:
        """Compile regex pattern for reuse."""
        try:
            self.compiled_pattern = re.compile(
                self.regex,
                re.IGNORECASE | re.MULTILINE
            )
        except re.error as e:
            logger.error(
                "Failed to compile sanitization pattern '%s': %s",
                self.name,
                e
            )
            self.enabled = False
    
    def apply(self, text: str) -> str:
        """Apply sanitization to text, return sanitized version."""
        if not self.enabled or not self.compiled_pattern or not text:
            return text
        
        try:
            matches = self.compiled_pattern.findall(text)
            if matches:
                self.match_count += len(matches)
                logger.debug(
                    "Pattern '%s' matched %d occurrences",
                    self.name,
                    len(matches)
                )
            
            sanitized = self.compiled_pattern.sub(self.replacement, text)
            return sanitized
        except Exception as e:
            logger.error(
                "Error applying pattern '%s': %s. Returning original text.",
                self.name,
                e
            )
            return text


class DeterministicSanitizer:
    """
    Sanitizes sensitive data before LLM context injection.
    
    Modes:
    - "off": No sanitization (default, backward compatible)
    - "moderate": Masks known patterns (API keys, passwords, tokens)
    - "strict": Also masks IPs, URLs, database schemas
    
    Example:
        sanitizer = DeterministicSanitizer(mode="moderate")
        clean_context = sanitizer.sanitize_text(dirty_text)
        clean_messages = sanitizer.sanitize_conversation(messages)
    """
    
    # Default patterns for "moderate" mode
    DEFAULT_PATTERNS = [
        SanitizationPattern(
            name="openai_api_key",
            regex=r"sk-[A-Za-z0-9_\-]{40,}",
            replacement="[REDACTED_OPENAI_KEY]"
        ),
        SanitizationPattern(
            name="aws_access_key",
            regex=r"AKIA[0-9A-Z]{16}",
            replacement="[REDACTED_AWS_KEY]"
        ),
        SanitizationPattern(
            name="anthropic_api_key",
            regex=r"sk-ant-[A-Za-z0-9_\-]{40,}",
            replacement="[REDACTED_ANTHROPIC_KEY]"
        ),
        SanitizationPattern(
            name="generic_api_key",
            regex=r"(?:api_?key|apikey|api-key)[\s:=]+['\"]?([a-zA-Z0-9_\-\.]+)['\"]?",
            replacement="[REDACTED_API_KEY]"
        ),
        SanitizationPattern(
            name="bearer_token",
            regex=r"Bearer\s+[A-Za-z0-9_\-\.]+",
            replacement="[REDACTED_TOKEN]"
        ),
        SanitizationPattern(
            name="github_token",
            regex=r"gh[ou]_[A-Za-z0-9_]{36,}",
            replacement="[REDACTED_GITHUB_TOKEN]"
        ),
        SanitizationPattern(
            name="password_assignment",
            regex=r"(?:password|pwd|passwd|secret)[\s:=]+['\"]?([^'\"\\s]+)['\"]?",
            replacement="[REDACTED_PASSWORD]"
        ),
        SanitizationPattern(
            name="aws_secret_key",
            regex=r"aws_secret_access_key\s*=\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
            replacement="aws_secret_access_key = [REDACTED_SECRET]"
        ),
        SanitizationPattern(
            name="connection_string",
            regex=r"(?:mongodb|mysql|postgres|sqlserver)://[^\s>\"]+",
            replacement="[REDACTED_CONNECTION_STRING]"
        ),
    ]
    
    # Additional patterns for "strict" mode
    STRICT_PATTERNS = DEFAULT_PATTERNS + [
        SanitizationPattern(
            name="private_ipv4",
            regex=r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
            replacement="[REDACTED_PRIVATE_IP]"
        ),
        SanitizationPattern(
            name="localhost_variations",
            regex=r"\b(?:localhost|127\.0\.0\.1|0\.0\.0\.0)\b",
            replacement="[REDACTED_LOCALHOST]"
        ),
        SanitizationPattern(
            name="database_url",
            regex=r"(?:postgresql|mysql|mongodb|redis)://[^\s>\"]+",
            replacement="[REDACTED_DB_URL]"
        ),
    ]
    
    def __init__(
        self,
        mode: str = "off",
        custom_patterns: Optional[List[SanitizationPattern]] = None
    ):
        """
        Initialize sanitizer.
        
        Args:
            mode: "off" (default), "moderate", or "strict"
            custom_patterns: Additional patterns to apply
        """
        self.mode = mode
        self.patterns: List[SanitizationPattern] = []
        self.stats = {"texts_sanitized": 0, "patterns_matched": 0}
        
        # Select patterns based on mode
        if mode == "strict":
            self.patterns = [p for p in self.STRICT_PATTERNS]
        elif mode == "moderate":
            self.patterns = [p for p in self.DEFAULT_PATTERNS]
        elif mode != "off":
            logger.warning(
                "Unknown sanitization mode '%s', using 'off'",
                mode
            )
            self.mode = "off"
        
        # Add custom patterns
        if custom_patterns:
            self.patterns.extend(custom_patterns)
        
        # Compile all patterns once for efficiency
        for pattern in self.patterns:
            pattern.compile()
        
        logger.info(
            "Initialized DeterministicSanitizer: mode=%s, patterns=%d",
            self.mode,
            len(self.patterns)
        )
    
    def sanitize_text(self, text: str) -> Tuple[str, int]:
        """
        Sanitize a single text string.
        
        Args:
            text: Raw text to sanitize
            
        Returns:
            Tuple of (sanitized_text, num_matches)
            
        Example:
            clean, matches = sanitizer.sanitize_text(dirty_text)
        """
        if not text or self.mode == "off":
            return text, 0
        
        total_matches = 0
        for pattern in self.patterns:
            if pattern.enabled:
                before_count = pattern.match_count
                text = pattern.apply(text)
                matches_in_pattern = pattern.match_count - before_count
                total_matches += matches_in_pattern
        
        self.stats["texts_sanitized"] += 1
        self.stats["patterns_matched"] += total_matches
        
        return text, total_matches
    
    def sanitize_message(self, message: Dict) -> Dict:
        """
        Sanitize a single message dict (e.g., from conversation history).
        
        Input:
            {"role": "user", "content": "My API key is sk-..."}
            
        Output:
            {"role": "user", "content": "My API key is [REDACTED_OPENAI_KEY]"}
        """
        sanitized = message.copy()
        
        # Sanitize main content
        if isinstance(sanitized.get("content"), str):
            sanitized["content"], _ = self.sanitize_text(sanitized["content"])
        
        # Sanitize tool calls arguments if present
        if "tool_calls" in sanitized:
            for tool_call in sanitized["tool_calls"]:
                if isinstance(tool_call.get("function", {}).get("arguments"), str):
                    tool_call["function"]["arguments"], _ = self.sanitize_text(
                        tool_call["function"]["arguments"]
                    )
        
        return sanitized
    
    def sanitize_conversation(self, messages: List[Dict]) -> List[Dict]:
        """
        Sanitize a full conversation history before sending to LLM.
        
        Input:
            [
                {"role": "system", "content": "...memory with secrets..."},
                {"role": "user", "content": "Debug my code with AWS key..."},
                {"role": "assistant", "content": "..."},
            ]
            
        Output:
            Same structure, but sensitive patterns redacted
        """
        if self.mode == "off":
            return messages
        
        return [self.sanitize_message(msg) for msg in messages]
    
    def sanitize_system_prompt(self, prompt: str) -> str:
        """
        Special handling for system prompt (contains MEMORY.md, context files, etc).
        
        More aggressive sanitization since system prompt is always sent to LLM.
        """
        sanitized, _ = self.sanitize_text(prompt)
        return sanitized
    
    def get_stats(self) -> Dict:
        """Return sanitization statistics."""
        return self.stats.copy()
    
    def reset_stats(self) -> None:
        """Reset sanitization statistics."""
        self.stats = {"texts_sanitized": 0, "patterns_matched": 0}


def get_sanitizer(config: Dict) -> DeterministicSanitizer:
    """
    Create sanitizer instance from config dict.
    
    Config format (config.yaml or dict):
        sanitization:
            enabled: true
            mode: "moderate"  # or "strict", "off"
            custom_patterns:
              - name: "company_domain"
                regex: "@company\\.com"
                replacement: "[REDACTED_DOMAIN]"
              - name: "custom_api"
                regex: "API_KEY_[A-Z0-9]{32}"
                replacement: "[REDACTED_CUSTOM]"
    
    Args:
        config: Configuration dictionary
        
    Returns:
        DeterministicSanitizer instance
        
    Example:
        from agent.sanitization_layer import get_sanitizer
        
        config = load_config()  # from hermes_cli.config
        sanitizer = get_sanitizer(config)
        clean_prompt = sanitizer.sanitize_system_prompt(system_prompt)
    """
    sanitization_config = config.get("sanitization", {})
    
    # Check if sanitization is enabled
    if not sanitization_config.get("enabled", False):
        return DeterministicSanitizer(mode="off")
    
    # Get sanitization mode
    mode = sanitization_config.get("mode", "moderate")
    
    # Build custom patterns
    custom_patterns = []
    for pattern_cfg in sanitization_config.get("custom_patterns", []):
        try:
            custom_patterns.append(
                SanitizationPattern(
                    name=pattern_cfg.get("name", "custom"),
                    regex=pattern_cfg.get("regex", r"(?!)"),  # No-match regex if not provided
                    replacement=pattern_cfg.get("replacement", "[REDACTED]"),
                    enabled=pattern_cfg.get("enabled", True)
                )
            )
        except KeyError as e:
            logger.error(
                "Invalid custom pattern config (missing %s), skipping",
                e
            )
            continue
    
    return DeterministicSanitizer(mode=mode, custom_patterns=custom_patterns)
