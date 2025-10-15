# Deep Eye - Contributing Guide

Thank you for your interest in contributing to Deep Eye! This document provides guidelines for contributing to the project.

## Code of Conduct

- Be respectful and professional
- Follow ethical security practices
- Never use this tool for illegal purposes
- Report security issues responsibly

## How to Contribute

### 1. Fork the Repository
```bash
git clone https://github.com/zakirkun/deep-eye.git
cd deep-eye
```

### 2. Create a Branch
```bash
git checkout -b feature/your-feature-name
```

### 3. Make Changes
- Follow PEP 8 style guidelines
- Add docstrings to all functions and classes
- Update tests if applicable
- Update documentation

### 4. Test Your Changes
```bash
python -m pytest tests/
```

### 5. Submit Pull Request
- Write clear commit messages
- Reference any related issues
- Update CHANGELOG.md

## Development Setup

### Install Development Dependencies
```powershell
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### Running Tests
```powershell
pytest tests/ -v
```

### Code Formatting
```powershell
# Format code
black .

# Check linting
flake8 .
```

## Project Structure

```
deep-eye/
├── core/               # Core scanning engine
├── ai_providers/       # AI provider integrations
├── modules/           # Security testing modules
├── utils/             # Utility functions
├── config/            # Configuration files
├── templates/         # Report templates
├── tests/             # Unit tests
└── examples/          # Usage examples
```

## Adding New Features

### Adding a New Vulnerability Check
1. Create test module in `modules/exploits/`
2. Implement detection logic
3. Add to vulnerability scanner
4. Update documentation

### Adding a New AI Provider
1. Create provider class in `ai_providers/`
2. Implement generate() method
3. Add to provider manager
4. Update configuration template

### Adding Report Formats
1. Create template in `templates/`
2. Implement generator in `report_generator.py`
3. Add format option to CLI
4. Update documentation

## Security

### Reporting Security Issues
- **DO NOT** open public issues for security vulnerabilities
- Email: security@deepeye.io
- Use PGP key if available
- Provide detailed reproduction steps

### Security Best Practices
- Never commit API keys or secrets
- Use environment variables for sensitive data
- Follow OWASP guidelines
- Implement rate limiting
- Add input validation

## Documentation

- Keep README.md up to date
- Add docstrings to all public APIs
- Update QUICKSTART.md for new features
- Include code examples

## Testing Guidelines

- Write unit tests for new features
- Maintain >80% code coverage
- Test edge cases
- Mock external API calls

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Questions?

Open an issue with the "question" label or contact the maintainers.

---

**Thank you for contributing to Deep Eye! 🔍🛡️**
