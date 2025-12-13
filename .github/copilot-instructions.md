# Copilot Instructions for LD Host Scanner

## Project Overview

LD Host Scanner is a Docker-based network security monitoring tool that performs automated port scanning (Rustscan for TCP, nmap for UDP) and sends alerts via email/webhooks (Discord/Slack).

## Code Review Guidelines

### Security Priorities

This is a security tool - code quality and security are paramount:

- **Input validation**: All user inputs must be validated. Use Pydantic models for API inputs.
- **Command injection**: Never pass unsanitized input to shell commands (subprocess, os.system).
- **SQL injection**: Always use parameterized queries via SQLAlchemy ORM, never raw SQL with string formatting.
- **Secrets**: Never log or expose credentials, API keys, or sensitive configuration values.

### Python Standards

- Python 3.11+ with type hints on all functions
- Async/await patterns for I/O operations (database, network, file)
- Use `logging` module, never `print()` statements
- Follow PEP 8 style guidelines
- Docstrings for public functions and classes

### Architecture Patterns

- **Async SQLAlchemy** with aiosqlite for database operations
- **FastAPI** for web endpoints with proper dependency injection
- **Pydantic Settings** for configuration from environment variables
- **APScheduler** for background job scheduling

### Testing Requirements

- Tests run inside Docker container
- Use pytest with pytest-asyncio for async tests
- Mock external dependencies (network calls, subprocess)
- Test edge cases and error conditions

### PR Review Checklist

When reviewing PRs, verify:

1. **Security**: No command injection, SQL injection, or exposed secrets
2. **Error handling**: Proper try/except blocks with meaningful error messages
3. **Logging**: Appropriate log levels (debug/info/warning/error)
4. **Type hints**: All functions have proper type annotations
5. **Async consistency**: No blocking calls in async functions
6. **Resource cleanup**: Database connections, file handles properly closed
7. **Configuration**: New settings added to `.env.example` and documented

### Common Issues to Flag

- Blocking I/O in async context (use `asyncio.to_thread()` for sync operations)
- Missing error handling for subprocess/network calls
- Hardcoded values that should be configurable
- Missing database migrations for schema changes
- Unpinned dependencies in requirements.txt

### File Structure

```
src/
├── main.py              # Entry point
├── config.py            # Pydantic settings
├── scanner/             # Port scanning logic
├── storage/             # Database models and operations
├── notifications/       # Email/webhook alerts
├── scheduler/           # Background jobs
└── web/                 # FastAPI routes and templates
```

### Commit Message Format

Use conventional commits:
- `feat:` new features
- `fix:` bug fixes
- `docs:` documentation changes
- `refactor:` code refactoring
- `test:` test additions/changes
- `chore:` maintenance tasks
