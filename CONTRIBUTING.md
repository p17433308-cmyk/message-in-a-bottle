# Contributing to FLOTSAM

Thank you for your interest in improving browser cache forensics.

## Scope

FLOTSAM is a **read-only DFIR** tool for hunting abuse in Service Worker Cache Storage. Contributions must:

- Never modify browser profiles or cached data
- Never require network access during analysis (offline-first)
- Maintain zero third-party dependencies in core

## How to Contribute

### Bug Reports
Open an issue with: OS, Python version, browser version (if applicable), full traceback, and the command you ran.

### Detection Rules
New abuse-detection rules are welcome. Each rule needs:
- A name following the existing convention (e.g., `cross-origin-entry`, `payload-signature`)
- A clear description of what it detects and why it matters
- A test case with fixture data
- A false-positive assessment

### Browser Support
FLOTSAM currently targets Chromium. Parsers for Firefox or Safari Cache Storage are welcome with:
- Format documentation or reverse-engineering notes
- Test fixtures from real browser profiles (sanitized)
- Integration with the existing hunt engine

### Documentation
Improvements to capture guides, analysis workflows, or format documentation.

## Development Setup

```bash
git clone https://github.com/p17433308-cmyk/message-in-a-bottle.git
cd message-in-a-bottle
pip install -e .
pytest tests/
```

## Code Style

- Python 3.9+, type hints encouraged
- Zero dependencies in core (native parsers only)
- Tests for every new rule and parser

## License

By contributing, you agree that your contributions will be licensed under the project's existing license.
