---
sidebar_position: 5
title: "Data Sanitization Layer"
description: "Optional sanitization of sensitive data before LLM context"
---

# Data Sanitization Layer

## Overview

Hermes Agent can optionally sanitize sensitive data before sending context to LLMs. This prevents accidental exfiltration of:

- API keys and tokens (OpenAI, AWS, Anthropic, GitHub, etc.)
- Passwords and credentials
- Private IPs and internal URLs
- Database connection strings
- Custom sensitive patterns

## ⚠️ Important Disclaimer

This is a **safety feature, NOT a guarantee**.

- Sanitization happens **before** sending to LLM, not in storage
- Your memory **still contains original data** (for your reference in Hermes)
- If you're storing secrets in memory, that's inherently risky
- This layer helps reduce accidental exposure, but best practice: **never store secrets in memory**

## Quick Start

### Enable Sanitization

Edit `~/.hermes/config.yaml`:

```yaml
sanitization:
  enabled: true
  mode: "moderate"
