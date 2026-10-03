# Contributing to QACyberWatch

Thank you for your interest in contributing to QACyberWatch! This project aims to protect Qatar's digital ecosystem from phishing and brand impersonation attacks.

## How to Contribute

### Reporting Bugs

1. Check existing [issues](https://github.com/SiteQ8/QACyberWatch/issues) first
2. Use the **Bug Report** issue template
3. Include steps to reproduce, expected vs. actual behavior
4. Add relevant logs or screenshots

### Suggesting Features

1. Open a **Feature Request** issue
2. Describe the use case and expected behavior
3. Explain how it fits the project's phishing detection mission

### Security Vulnerabilities

**DO NOT** open public issues for security vulnerabilities. See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

### Pull Requests

1. **Fork** the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Write tests for new functionality
4. Ensure all tests pass: `pytest tests/`
5. Follow the code style (Black formatter, flake8 linting)
6. Update documentation as needed
7. Submit a PR using the PR template

### Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/QACyberWatch.git
cd QACyberWatch

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

# Run tests
pytest tests/ -v

# Run linting (settings live in .flake8 and pyproject.toml)
flake8 src/ tests/ main.py
black --check src/ tests/ main.py
```

### Code Style

- **Python**: Follow PEP 8, use Black formatter (line length 100)
- **Type hints**: Required for all public functions
- **Docstrings**: Google-style docstrings for modules, classes, and functions
- **Tests**: Minimum 80% coverage for new code; tests must run offline (mock network calls)

### Commit Messages

Use conventional commits:
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `test:` Adding/updating tests
- `refactor:` Code refactoring
- `chore:` Maintenance tasks
- `security:` Security-related changes

### Areas Needing Help

- Additional brand profiles for Qatar organizations
- Threat intelligence feed integrations
- Machine learning model improvements
- Arabic language support
- Documentation and tutorials
- Testing and QA

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Questions?

Reach out to **Ali AlEnezi** at Site@hotmail.com or open a Discussion on GitHub.
