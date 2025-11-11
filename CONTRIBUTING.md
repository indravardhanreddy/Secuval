# Contributing to SecureAPIs

Thank you for your interest in contributing to SecureAPIs! This document provides guidelines for contributing to the project.

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help maintain a welcoming environment

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in Issues
2. Create a new issue with:
   - Clear title and description
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Rust version, etc.)

### Suggesting Enhancements

1. Check existing issues for similar suggestions
2. Create a new issue describing:
   - The problem you're trying to solve
   - Your proposed solution
   - Alternative solutions considered

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass (`cargo test`)
6. Run benchmarks if performance-critical (`cargo bench`)
7. Format your code (`cargo fmt`)
8. Lint your code (`cargo clippy`)
9. Commit your changes with clear messages
10. Push to your fork
11. Open a Pull Request

### Code Style

- Follow Rust standard style guide
- Use `cargo fmt` for formatting
- Address all `cargo clippy` warnings
- Add documentation for public APIs
- Include examples where appropriate

### Testing

- Add unit tests for new functionality
- Add integration tests for major features
- Ensure existing tests still pass
- Aim for high code coverage

### Performance

- Run benchmarks for performance-critical changes
- Document any performance implications
- Avoid unnecessary allocations
- Use efficient algorithms and data structures

## Development Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/secureapis.git
cd secureapis

# Build the project
cargo build

# Run tests
cargo test

# Run benchmarks
cargo bench

# Check formatting
cargo fmt --check

# Run linter
cargo clippy
```

## Security Vulnerabilities

**DO NOT** open public issues for security vulnerabilities. Instead, email security@secureapis.org with:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will respond within 48 hours and work with you to address the issue.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
