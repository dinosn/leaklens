# Contributing to LeakLens

Thank you for your interest in contributing to LeakLens, a web-aware secrets scanner for source code, Git history, local files, direct URLs, and JavaScript-heavy web applications.

We welcome contributions of all kinds -- bug reports, feature requests, documentation improvements, and code changes.

## Reporting Bugs

If you find a bug, please open a [GitHub Issue](https://github.com/dinosn/leaklens/issues) with the following information:

- A clear, descriptive title
- Steps to reproduce the problem
- Expected behavior vs. actual behavior
- Your environment (OS, Go version, etc.)
- Any relevant log output or error messages

## Suggesting Features

Feature requests are tracked as [GitHub Issues](https://github.com/dinosn/leaklens/issues). When suggesting a feature, please include:

- A clear description of the problem the feature would solve
- Your proposed solution or approach
- Any alternatives you have considered

## Development Setup

### Prerequisites

- **Go 1.25.7+**
- **make**

### Building

```bash
# Build a portable pure-Go CLI binary
make build-pure

# Build with Vectorscan/Hyperscan acceleration when native libraries are installed
make build

# Build a static binary
make build-static
```

### Testing

```bash
make test
```

## Pull Request Process

1. **Fork** the repository and create a feature branch from `main`.
2. **Make your changes** in the feature branch.
3. **Add or update tests** to cover your changes.
4. **Ensure all tests pass** by running `make test`.
5. **Push** your branch to your fork.
6. **Open a Pull Request** against `main` with a clear description of your changes.

A maintainer will review your PR and may request changes. Once approved, a maintainer will merge it.

### PR Guidelines

- Keep pull requests focused on a single change.
- Write clear commit messages that explain the "why" behind the change.
- Reference any related issues in the PR description (e.g., "Fixes #42").

## Code Style

- Run `go fmt` on all Go code before committing.
- Run `go vet` to catch common issues.
- Follow standard Go conventions and idioms.
- Keep functions short and well-named.
- Add comments for exported types and functions.

## Testing Expectations

- All new features should include tests.
- Bug fixes should include a test that reproduces the issue.
- Aim to maintain or improve overall test coverage.
- Tests should be deterministic and not depend on external services.

## License

LeakLens is licensed under the [Apache License 2.0](LICENSE). By contributing to this project, you agree that your contributions will be licensed under the same license.
