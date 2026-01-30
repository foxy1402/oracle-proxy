# Contributing to Oracle Cloud Proxy

Thank you for your interest in contributing! This project aims to make Oracle Cloud proxy setup simple and secure.

## How to Contribute

### Reporting Bugs

If you find a bug, please open an issue with:
- Oracle Linux version
- Instance type (Free Tier / Paid)
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs (from health-check.sh)

### Suggesting Features

Feature suggestions are welcome! Please include:
- Use case description
- Why this would be useful
- Proposed implementation (optional)

### Code Contributions

1. **Fork the repository**
   ```bash
   git clone https://github.com/foxy1402/oracle-proxy.git
   cd oracle-proxy
   ```

2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**
   - Follow existing code style
   - Add comments for complex logic
   - Test on Oracle Linux 8
   - Update documentation if needed

4. **Test thoroughly**
   - Test on clean Oracle Linux 8 instance
   - Run health-check.sh
   - Verify all features work
   - Check security implications

5. **Commit your changes**
   ```bash
   git add .
   git commit -m "Add: brief description of changes"
   ```

6. **Push and create Pull Request**
   ```bash
   git push origin feature/your-feature-name
   ```
   Then open a PR on GitHub

## Development Guidelines

### Code Style

**Bash Scripts:**
- Use `#!/bin/bash` shebang
- Add function comments
- Use descriptive variable names
- Handle errors properly
- Quote variables: `"$VARIABLE"`

**Python (Dashboard):**
- Follow PEP 8
- Use type hints where possible
- Validate all user inputs
- Use secure coding practices

### Security

**Critical:**
- Never store passwords in plain text
- Always validate user inputs
- Avoid shell injection vulnerabilities
- Use least privilege principle
- Document security implications

### Testing

Before submitting:
- [ ] Tested on Oracle Linux 8
- [ ] Verified SOCKS5 proxy works
- [ ] Verified HTTP proxy works
- [ ] Dashboard accessible and functional
- [ ] Health check passes
- [ ] No security regressions
- [ ] Documentation updated

## Areas We Need Help

- **Documentation** - Improve guides, add examples
- **Testing** - Test on different Oracle Cloud regions
- **Security** - Security audits and improvements
- **Features** - HTTPS support, monitoring, etc.
- **Localization** - Translate documentation

## Security Issues

**DO NOT** open public issues for security vulnerabilities.

Please report security issues privately via:
- GitHub Security Advisories
- Email to repository maintainer

Include:
- Vulnerability description
- Steps to reproduce
- Potential impact
- Suggested fix (optional)

## Code of Conduct

- Be respectful and constructive
- Help others learn
- Focus on the problem, not the person
- Welcome newcomers

## Questions?

- Open a GitHub Discussion
- Check existing issues
- Read the documentation first

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for contributing!** 🎉
