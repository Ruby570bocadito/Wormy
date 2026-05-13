# Contributing to Wormy

## Code Style

- All Python code must pass `black . --check` and `isort --check-only .`
- Maximum line length: 100 characters
- Use type hints for all function signatures
- Use `logger` for all output (never `print()` in production code)
- Handle exceptions with specific types and always log via `logger.exception()`

## Pull Request Process

1. Run `pre-commit run --all-files` before committing
2. Ensure all tests pass: `pytest tests/ -v`
3. Update CHANGELOG.md with your changes
4. Update README.md if adding new exploits or features

## Security

- Never commit hardcoded credentials, API keys, or tokens
- Use `os.getenv()` with descriptive fallback values for secrets
- Never use `shell=True` in subprocess calls
- Avoid `exec()` and `eval()` in production code
- Report security vulnerabilities per SECURITY.md
